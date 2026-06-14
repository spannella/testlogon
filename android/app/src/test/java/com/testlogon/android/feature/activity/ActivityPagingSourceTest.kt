package com.testlogon.android.feature.activity

import androidx.paging.PagingSource
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-096 — direct PagingSource.load() assertions: refresh, append, end-of-pagination, error. */
class ActivityPagingSourceTest {

    @Test
    fun refresh_returnsFirstPage_keyedByCursor() = runTest {
        val repo = FakeActivityRepository(
            pagesByCursor = mapOf(
                null to FakeActivityRepository.page(
                    listOf(FakeActivityRepository.event("a1"), FakeActivityRepository.event("a2")),
                    nextCursor = "c2",
                ),
            ),
        )
        val source = ActivityPagingSource(repo)
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("a1", "a2"), page.data.map { it.id })
        assertNull(page.prevKey)
        assertEquals("c2", page.nextKey)
    }

    @Test
    fun append_returnsNextPage_endsWhenCursorNull() = runTest {
        val repo = FakeActivityRepository(
            pagesByCursor = mapOf(
                "c2" to FakeActivityRepository.page(
                    listOf(FakeActivityRepository.event("a3")),
                    nextCursor = null,
                ),
            ),
        )
        val source = ActivityPagingSource(repo)
        val result = source.load(PagingSource.LoadParams.Append("c2", 20, false))

        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("a3"), page.data.map { it.id })
        assertNull(page.nextKey) // end of pagination
    }

    @Test
    fun failure_becomesLoadResultError() = runTest {
        val repo = FakeActivityRepository().apply { feedResult = FakeActivityRepository.failure(500) }
        val source = ActivityPagingSource(repo)
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }

    @Test
    fun networkError_becomesLoadResultError() = runTest {
        val repo = FakeActivityRepository().apply {
            feedResult = ApiResult.NetworkError(java.io.IOException("offline"))
        }
        val source = ActivityPagingSource(repo)
        val result = source.load(PagingSource.LoadParams.Refresh(null, 20, false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
