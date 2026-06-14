package com.testlogon.android.feature.earnings.percontent

import androidx.paging.PagingSource
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.earnings.ContentRevenue
import com.testlogon.android.data.earnings.ContentRevenuePage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ContentRevenuePagingSourceTest {

    private fun row(id: String) = ContentRevenue(id, "post", id, 0, 0, 0, 0, 0, 0, 100)

    private fun page(items: List<String>, next: String?) = ContentRevenuePage(
        items = items.map { row(it) },
        totalItems = 137,
        totalRevenueCents = 9999,
        currency = "USD",
        nextCursor = next,
    )

    @Test
    fun firstPage_returnsItems_nextKey_andFiresHeaderOnce() = runTest {
        var headerCalls = 0
        val source = ContentRevenuePagingSource(
            load = { cursor, _ ->
                when (cursor) {
                    null -> ApiResult.Success(page(listOf("a", "b"), "c1"))
                    "c1" -> ApiResult.Success(page(listOf("c"), null))
                    else -> ApiResult.Success(page(emptyList(), null))
                }
            },
            onHeader = { headerCalls++ },
        )

        val first = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 50, placeholdersEnabled = false))
        assertTrue(first is PagingSource.LoadResult.Page)
        first as PagingSource.LoadResult.Page
        assertEquals(2, first.data.size)
        assertNull(first.prevKey)
        assertEquals("c1", first.nextKey)
        assertEquals(1, headerCalls)

        val second = source.load(PagingSource.LoadParams.Append(key = "c1", loadSize = 50, placeholdersEnabled = false))
        second as PagingSource.LoadResult.Page
        assertEquals(1, second.data.size)
        assertNull(second.nextKey) // paging stops
        // header NOT fired again on a non-first page
        assertEquals(1, headerCalls)
    }

    @Test
    fun failure_returnsLoadResultError() = runTest {
        val source = ContentRevenuePagingSource(
            load = { _, _ -> ApiResult.Failure(ApiError(status = 422, message = "bad sort")) },
            onHeader = {},
        )
        val result = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 50, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
        result as PagingSource.LoadResult.Error
        assertTrue(result.throwable is ContentRevenueLoadException)
        assertEquals("bad sort", result.throwable.message)
    }

    @Test
    fun networkError_returnsCauseAsError() = runTest {
        val cause = java.io.IOException("offline")
        val source = ContentRevenuePagingSource(
            load = { _, _ -> ApiResult.NetworkError(cause) },
            onHeader = {},
        )
        val result = source.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 50, placeholdersEnabled = false))
        result as PagingSource.LoadResult.Error
        assertEquals(cause, result.throwable)
    }
}
