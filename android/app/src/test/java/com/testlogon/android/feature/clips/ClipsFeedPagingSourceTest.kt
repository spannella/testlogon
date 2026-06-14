package com.testlogon.android.feature.clips

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.ClipsPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** AND-198 — [ClipsFeedPagingSource] via TestPager: next_cursor forwarding, terminal page, errors. */
class ClipsFeedPagingSourceTest {

    private val config = PagingConfig(pageSize = 10, initialLoadSize = 10, enablePlaceholders = false)
    private val repo = FakeClipsRepository()

    private fun source() = ClipsFeedPagingSource(repo)

    @Test
    fun firstPage_nullCursor_pageWithNextKey_prevNull() = runTest {
        repo.pages[null] = ApiResult.Success(
            ClipsPage(listOf(FakeClipsRepository.sampleClip("clp_1")), nextCursor = "cur2"),
        )
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("clp_1"), result.data.map { it.clipId })
        assertEquals("cur2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun append_forwardsCursor_terminatesOnNull() = runTest {
        repo.pages[null] = ApiResult.Success(
            ClipsPage(listOf(FakeClipsRepository.sampleClip("clp_1")), nextCursor = "cur2"),
        )
        repo.pages["cur2"] = ApiResult.Success(
            ClipsPage(listOf(FakeClipsRepository.sampleClip("clp_2")), nextCursor = null),
        )
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("clp_2"), appended.data.map { it.clipId })
        assertNull(appended.nextKey)
        assertTrue(repo.requestedCursors.contains("cur2"))
    }

    @Test
    fun empty_terminalPage() = runTest {
        repo.pages[null] = ApiResult.Success(ClipsPage(emptyList(), nextCursor = null))
        val result = TestPager(config, source()).refresh() as PagingSource.LoadResult.Page
        assertTrue(result.data.isEmpty())
        assertNull(result.nextKey)
    }

    @Test
    fun httpFailure_yieldsClipsLoadException() = runTest {
        repo.pages[null] = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val result = TestPager(config, source()).refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is ClipsLoadException)
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
