package com.testlogon.android.feature.fanclub

import androidx.paging.PagingSource
import androidx.paging.PagingState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubMemberPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-239/240 — PagingSource cursor threading + end-of-pagination + error mapping. */
class FanClubPagingSourceTest {

    // ---- AND-239: channel messages (client-derived `before` cursor; no server has_more) ----

    @Test
    fun messages_firstPageFull_nextKeyIsOldestId() = runTest {
        val full = (1..30).map { FakeFanClubRepository.message("m$it") }
        val repo = FakeFanClubRepository(messagePages = mapOf(null to ApiResult.Success(full)))
        val source = ChannelMessagesPagingSource(repo, "c")

        val result = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 30, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals("m30", page.nextKey) // oldest item id = next `before`
        assertNull(page.prevKey)
    }

    @Test
    fun messages_shortPage_endsPagination() = runTest {
        val short = (1..12).map { FakeFanClubRepository.message("m$it") }
        val repo = FakeFanClubRepository(messagePages = mapOf("m30" to ApiResult.Success(short)))
        val source = ChannelMessagesPagingSource(repo, "c")

        val result = source.load(PagingSource.LoadParams.Append(key = "m30", loadSize = 30, placeholdersEnabled = false))
        val page = result as PagingSource.LoadResult.Page
        assertNull(page.nextKey) // size < limit -> end
    }

    @Test
    fun messages_failure_returnsLoadResultError() = runTest {
        val repo = FakeFanClubRepository(messagePages = mapOf(null to FakeFanClubRepository.failure(status = 500)))
        val source = ChannelMessagesPagingSource(repo, "c")
        val result = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 30, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    // ---- AND-240: tier members (server cursor) ----

    @Test
    fun members_threadsCursor_andEndsOnNull() = runTest {
        val repo = FakeFanClubRepository(
            memberPages = mapOf(
                null to FanClubMemberPage(listOf(FakeFanClubRepository.member("u1")), nextCursor = "c2", total = 2),
                "c2" to FanClubMemberPage(listOf(FakeFanClubRepository.member("u2")), nextCursor = null, total = 2),
            ),
        )
        val source = TierMembersPagingSource(repo, "tier_gold")

        val p1 = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 50, placeholdersEnabled = false))
            as PagingSource.LoadResult.Page
        assertEquals("c2", p1.nextKey)

        val p2 = source.load(PagingSource.LoadParams.Append(key = "c2", loadSize = 50, placeholdersEnabled = false))
            as PagingSource.LoadResult.Page
        assertNull(p2.nextKey)
    }

    @Test
    fun members_error_returnsLoadResultError() = runTest {
        val repo = FakeFanClubRepository(memberResultOverride = FakeFanClubRepository.failure(status = 503))
        val source = TierMembersPagingSource(repo, "tier_gold")
        val result = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 50, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    @Test
    fun members_getRefreshKey_isNull() {
        val source = TierMembersPagingSource(FakeFanClubRepository(), "t")
        assertNull(source.getRefreshKey(PagingState(emptyList(), null, androidx.paging.PagingConfig(50), 0)))
    }
}
