package com.testlogon.android.feature.videos

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.VideoPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** AND-189 — [VideosPagingSource] via TestPager: cursor forwarding, terminal page, error mapping. */
class VideosPagingSourceTest {

    private val config = PagingConfig(pageSize = 24, initialLoadSize = 24, enablePlaceholders = false)
    private val repo = FakeVideosRepository()

    private fun source() = VideosPagingSource(repo)

    @Test
    fun firstPage_nullCursor_pageWithNextKey_prevNull() = runTest {
        repo.pages[null] = ApiResult.Success(VideoPage(listOf(FakeVideosRepository.summary("v1")), cursor = "c1"))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("v1"), result.data.map { it.id })
        assertEquals("c1", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_forwardsCursor_terminatesOnNull() = runTest {
        repo.pages[null] = ApiResult.Success(VideoPage(listOf(FakeVideosRepository.summary("v1")), cursor = "c1"))
        repo.pages["c1"] = ApiResult.Success(VideoPage(listOf(FakeVideosRepository.summary("v2")), cursor = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("v2"), appended.data.map { it.id })
        assertNull(appended.nextKey)
        assertTrue(repo.requestedCursors.contains("c1"))
    }

    @Test
    fun empty_200_terminalPage() = runTest {
        repo.pages[null] = ApiResult.Success(VideoPage(emptyList(), cursor = null))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertTrue(result.data.isEmpty())
        assertNull(result.nextKey)
    }

    @Test
    fun httpFailure_yieldsVideosLoadException() = runTest {
        repo.pages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is VideosLoadException)
    }

    @Test
    fun networkError_yieldsLoadResultError() = runTest {
        repo.pages[null] = ApiResult.NetworkError(IOException("offline"))
        assertTrue(TestPager(config, source()).refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}
