package com.testlogon.android.feature.payouts

import androidx.paging.PagingSource
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.payouts.Payout
import com.testlogon.android.data.payouts.PayoutPage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-260 — [PayoutsPagingSource] load behavior: first page + cursor threading, end-of-pagination when
 * next_cursor is null, mapped Failure -> LoadResult.Error(PayoutsLoadException), NetworkError ->
 * LoadResult.Error(cause), and that loaded rows are pushed to the onLoaded cache hook. Drives load()
 * directly (no asSnapshot on a hand-built source, per the gotcha).
 */
class PayoutsPagingSourceTest {

    private fun source(repo: FakePayoutsRepository, onLoaded: (List<Payout>) -> Unit = {}) =
        PayoutsPagingSource(repo, pageSize = 20, onLoaded = onLoaded)

    @Test
    fun load_firstPage_returnsRows_nextKey_andFeedsCache() = runTest {
        val repo = FakePayoutsRepository().apply {
            pages = mutableMapOf(
                null to ApiResult.Success(PayoutPage(listOf(samplePayout("po_1")), nextCursor = "c2")),
            )
        }
        val cached = mutableListOf<Payout>()
        val result = source(repo) { cached += it }
            .load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(1, page.data.size)
        assertEquals("c2", page.nextKey)
        assertNull(page.prevKey)
        assertEquals(listOf("po_1"), cached.map { it.payoutId })
    }

    @Test
    fun load_appendPage_threadsCursor_endsWhenNextCursorNull() = runTest {
        val repo = FakePayoutsRepository().apply {
            pages = mutableMapOf(
                "c2" to ApiResult.Success(PayoutPage(listOf(samplePayout("po_2")), nextCursor = null)),
            )
        }
        val result = source(repo)
            .load(PagingSource.LoadParams.Append(key = "c2", loadSize = 20, placeholdersEnabled = false))
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf<String?>("c2"), repo.requestedCursors)
        assertNull(page.nextKey)
    }

    @Test
    fun load_failure_mapsToLoadException() = runTest {
        val repo = FakePayoutsRepository().apply {
            pages = mutableMapOf(null to ApiResult.Failure(ApiError(status = 500, message = "boom")))
        }
        val result = source(repo)
            .load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
        val error = (result as PagingSource.LoadResult.Error).throwable
        assertTrue(error is PayoutsLoadException)
        assertEquals("boom", error.message)
    }

    @Test
    fun load_networkError_propagatesCause() = runTest {
        val repo = FakePayoutsRepository().apply {
            pages = mutableMapOf(null to ApiResult.NetworkError(IOException("offline")))
        }
        val result = source(repo)
            .load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue((result as PagingSource.LoadResult.Error).throwable is IOException)
    }
}
