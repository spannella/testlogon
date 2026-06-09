package com.testlogon.android.feature.feed

import androidx.paging.PagingConfig
import androidx.paging.PagingSource
import androidx.paging.testing.TestPager
import com.testlogon.android.data.feed.FeedPage
import com.testlogon.android.data.feed.FeedPost
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-098 / AND-104 — [FeedPagingSource] load/append/end/error tests via Paging's TestPager. */
class FeedPagingSourceTest {

    private val config = PagingConfig(pageSize = 20, initialLoadSize = 20, enablePlaceholders = false)

    @Test
    fun firstPage_returnsPageWithNextKey_prevNull() = runTest {
        val repo = FakeFeedRepository(
            pagesByCursor = mapOf(
                null to FeedPage(listOf(FakeFeedRepository.post("p1")), nextCursor = "c2"),
            ),
        )
        val pager = TestPager(config, FeedPagingSource(repo))
        val result = pager.refresh() as PagingSource.LoadResult.Page
        assertEquals(listOf("p1"), result.data.map(FeedPost::id))
        assertEquals("c2", result.nextKey)
        assertNull(result.prevKey)
    }

    @Test
    fun appendThenTerminalPage_nextKeyNull() = runTest {
        val repo = FakeFeedRepository(
            pagesByCursor = mapOf(
                null to FeedPage(listOf(FakeFeedRepository.post("p1")), nextCursor = "c2"),
                "c2" to FeedPage(listOf(FakeFeedRepository.post("p2")), nextCursor = null),
            ),
        )
        val pager = TestPager(config, FeedPagingSource(repo))
        pager.refresh()
        val appended = pager.append() as PagingSource.LoadResult.Page
        assertEquals(listOf("p2"), appended.data.map(FeedPost::id))
        assertNull(appended.nextKey)
    }

    @Test
    fun failure_yieldsLoadResultError() = runTest {
        val repo = FakeFeedRepository().apply { feedResult = FakeFeedRepository.failure(500) }
        val pager = TestPager(config, FeedPagingSource(repo))
        val result = pager.refresh()
        assertTrue(result is PagingSource.LoadResult.Error)
        assertTrue((result as PagingSource.LoadResult.Error).throwable is FeedLoadException)
    }

    @Test
    fun networkError_yieldsLoadResultError() = runTest {
        val repo = FakeFeedRepository().apply { feedResult = FakeFeedRepository.network() }
        val pager = TestPager(config, FeedPagingSource(repo))
        assertTrue(pager.refresh() is PagingSource.LoadResult.Error)
    }

    @Test
    fun getRefreshKey_isNull() {
        val source = FeedPagingSource(FakeFeedRepository())
        assertNull(source.getRefreshKey(androidx.paging.PagingState(emptyList(), null, config, 0)))
    }
}
