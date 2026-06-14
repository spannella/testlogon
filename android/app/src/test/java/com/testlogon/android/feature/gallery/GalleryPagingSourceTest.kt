package com.testlogon.android.feature.gallery

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.gallery.GalleryCategory
import com.testlogon.android.data.gallery.GalleryPage
import com.testlogon.android.data.gallery.GalleryRepository
import com.testlogon.android.data.gallery.GalleryVideoItem
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** AND-201 — [GalleryPagingSource] tests via Paging's TestPager: cursor follow, terminal, errors, search. */
class GalleryPagingSourceTest {

    private val config = PagingConfig(pageSize = 48, initialLoadSize = 48, enablePlaceholders = false)
    private val repo = FakeGalleryRepository()

    private fun item(id: String) = GalleryVideoItem(videoId = id, title = "t-$id", ownerUserId = "o")

    private fun source(category: String? = null, query: String? = null) =
        GalleryPagingSource(repo, category, query)

    @Test
    fun firstPage_followsCursor_prevNull() = runTest {
        repo.browsePages[null] = ApiResult.Success(GalleryPage(listOf(item("v1")), emptyList(), cursor = "c2"))
        val pager = TestPager(config, source())
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("v1"), result.data.map { it.videoId })
        assertEquals("c2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun appendFollowsCursor_terminatesOnNull() = runTest {
        repo.browsePages[null] = ApiResult.Success(GalleryPage(listOf(item("v1")), emptyList(), cursor = "c2"))
        repo.browsePages["c2"] = ApiResult.Success(GalleryPage(listOf(item("v2")), emptyList(), cursor = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("v2"), appended.data.map { it.videoId })
        assertNull(appended.nextKey)
    }

    @Test
    fun singlePage_nullCursor_noAppend() = runTest {
        repo.browsePages[null] = ApiResult.Success(GalleryPage(listOf(item("v1")), emptyList(), cursor = null))
        val pager = TestPager(config, source())
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertNull(result.nextKey)
    }

    @Test
    fun search_usesSearchPath() = runTest {
        repo.searchPages[null] = ApiResult.Success(GalleryPage(listOf(item("s1")), emptyList(), cursor = null))
        val pager = TestPager(config, source(query = "bay"))
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("s1"), result.data.map { it.videoId })
        assertTrue(repo.searchedQueries.contains("bay"))
    }

    @Test
    fun httpFailure_yieldsGalleryLoadException() = runTest {
        repo.browsePages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = (TestPager(config, source())).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is GalleryLoadException)
    }

    @Test
    fun networkError_yieldsError() = runTest {
        repo.browsePages[null] = ApiResult.NetworkError(IOException("offline"))
        assertTrue((TestPager(config, source())).refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}

/** Test double for [GalleryRepository] keyed by cursor. */
class FakeGalleryRepository : GalleryRepository {
    val browsePages = mutableMapOf<String?, ApiResult<GalleryPage>>()
    val searchPages = mutableMapOf<String?, ApiResult<GalleryPage>>()
    val searchedQueries = mutableListOf<String>()
    var categoriesResult: ApiResult<List<GalleryCategory>> = ApiResult.Success(emptyList())

    override suspend fun browse(category: String?, cursor: String?, limit: Int): ApiResult<GalleryPage> =
        browsePages[cursor] ?: ApiResult.Success(GalleryPage(emptyList(), emptyList(), null))

    override suspend fun search(query: String, cursor: String?, limit: Int): ApiResult<GalleryPage> {
        searchedQueries += query
        return searchPages[cursor] ?: ApiResult.Success(GalleryPage(emptyList(), emptyList(), null))
    }

    override suspend fun categories(): ApiResult<List<GalleryCategory>> = categoriesResult
}
