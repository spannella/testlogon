package com.testlogon.android.feature.vod

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.VodPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** AND-191 — [VodCatalogPagingSource] via TestPager: cursor forwarding, terminal page, errors. */
class VodCatalogPagingSourceTest {

    private val config = PagingConfig(pageSize = 30, initialLoadSize = 30, enablePlaceholders = false)
    private val repo = FakeVodRepository()

    private fun source(category: String? = null) = VodCatalogPagingSource(repo, category = category)

    @Test
    fun firstPage_pageWithNextKey() = runTest {
        repo.pages["|"] = ApiResult.Success(VodPage(listOf(FakeVodRepository.summary("v1")), cursor = "c1"))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("v1"), result.data.map { it.id })
        assertEquals("c1", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_forwardsCursor_terminatesOnNull() = runTest {
        repo.pages["|"] = ApiResult.Success(VodPage(listOf(FakeVodRepository.summary("v1")), cursor = "c1"))
        repo.pages["|c1"] = ApiResult.Success(VodPage(listOf(FakeVodRepository.summary("v2")), cursor = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("v2"), appended.data.map { it.id })
        assertNull(appended.nextKey)
    }

    @Test
    fun categoryFilter_isForwarded() = runTest {
        repo.pages["comedy|"] = ApiResult.Success(VodPage(listOf(FakeVodRepository.summary("vc")), cursor = null))
        val result = TestPager(config, source(category = "comedy")).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("vc"), result.data.map { it.id })
        assertTrue(repo.requests.contains("comedy|"))
    }

    @Test
    fun httpFailure_yieldsVodLoadException() = runTest {
        repo.pages["|"] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is VodLoadException)
    }

    @Test
    fun networkError_yieldsLoadResultError() = runTest {
        repo.pages["|"] = ApiResult.NetworkError(IOException("offline"))
        assertTrue(TestPager(config, source()).refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}
