package com.testlogon.android.feature.discover

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.TestPager
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.discover.TagPostPage
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.Paywall
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** AND-183 — [TagPagingSource] tests via Paging's TestPager: cursor forwarding, terminal page, errors. */
class TagPagingSourceTest {

    private val config = PagingConfig(pageSize = 24, initialLoadSize = 24, enablePlaceholders = false)
    private val repo = FakeTagRepository()

    private fun post(id: String) = FeedPost(
        id = id,
        authorId = "a",
        createdAtEpochSeconds = 0,
        body = "b",
        media = emptyList(),
        tags = emptyList(),
        likeCount = 0,
        commentCount = 0,
        likedByMe = false,
        paywall = Paywall.Unlocked,
    )

    private fun source() = TagPagingSource(repo, "kotlin")

    @Test
    fun firstPage_nullCursor_pageWithNextKey_prevNull() = runTest {
        repo.pages[null] = ApiResult.Success(TagPostPage(listOf(post("p1")), nextCursor = "c1"))
        val pager = TestPager(config, source())
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("p1"), result.data.map { it.id })
        assertEquals("c1", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun appendForwardsCursor_terminatesOnNull() = runTest {
        repo.pages[null] = ApiResult.Success(TagPostPage(listOf(post("p1")), nextCursor = "c1"))
        repo.pages["c1"] = ApiResult.Success(TagPostPage(listOf(post("p2")), nextCursor = null))
        val pager = TestPager(config, source())
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("p2"), appended.data.map { it.id })
        assertNull(appended.nextKey)
        assertTrue(repo.cursors.contains("c1"))
    }

    @Test
    fun emptyTag_200_emptyPage_terminal() = runTest {
        repo.pages[null] = ApiResult.Success(TagPostPage(emptyList(), nextCursor = null))
        val pager = TestPager(config, source())
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertTrue(result.data.isEmpty())
        assertNull(result.nextKey)
    }

    @Test
    fun httpFailure_yieldsLoadResultError_tagLoadException() = runTest {
        repo.pages[null] = ApiResult.Failure(ApiError(status = 422, message = "bad"))
        val pager = TestPager(config, source())
        val result = pager.refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is TagLoadException)
    }

    @Test
    fun networkError_yieldsLoadResultError() = runTest {
        repo.pages[null] = ApiResult.NetworkError(IOException("offline"))
        val pager = TestPager(config, source())
        assertTrue(pager.refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        assertNull(source().getRefreshKey(PagingState(emptyList(), null, config, 0)))
    }
}
