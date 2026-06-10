package com.testlogon.android.feature.invoices

import androidx.paging.PagingSource
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.invoices.InvoicePage
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-243 — [InvoicesPagingSource] load behavior: first page + cursor threading, end-of-pagination when
 * next_cursor is null, mapped Failure -> LoadResult.Error(InvoicesLoadException), NetworkError ->
 * LoadResult.Error(cause). Drives load() directly (deterministic; no asSnapshot on a hand-built source).
 */
class InvoicesPagingSourceTest {

    private fun source(repo: FakeInvoicesRepository) = InvoicesPagingSource(repo, pageSize = 20)

    @Test
    fun load_firstPage_returnsRows_andNextKey() = runTest {
        val repo = FakeInvoicesRepository().apply {
            pages = mutableMapOf(
                null to ApiResult.Success(InvoicePage(listOf(sampleInvoiceSummary("INV-1")), nextCursor = "c2")),
            )
        }
        val result = source(repo).load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(1, page.data.size)
        assertEquals("c2", page.nextKey)
        assertNull(page.prevKey)
    }

    @Test
    fun load_appendPage_threadsCursor_andEndsWhenNextCursorNull() = runTest {
        val repo = FakeInvoicesRepository().apply {
            pages = mutableMapOf(
                "c2" to ApiResult.Success(InvoicePage(listOf(sampleInvoiceSummary("INV-2")), nextCursor = null)),
            )
        }
        val result = source(repo).load(PagingSource.LoadParams.Append(key = "c2", loadSize = 20, placeholdersEnabled = false))
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf<String?>("c2"), repo.requestedCursors)
        assertNull("next_cursor==null drives endOfPaginationReached", page.nextKey)
    }

    @Test
    fun load_failure_mapsToLoadException() = runTest {
        val repo = FakeInvoicesRepository().apply {
            pages = mutableMapOf(null to ApiResult.Failure(ApiError(status = 500, message = "boom")))
        }
        val result = source(repo).load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
        val error = (result as PagingSource.LoadResult.Error).throwable
        assertTrue(error is InvoicesLoadException)
        assertEquals("boom", error.message)
    }

    @Test
    fun load_networkError_propagatesCause() = runTest {
        val repo = FakeInvoicesRepository().apply {
            pages = mutableMapOf(null to ApiResult.NetworkError(IOException("offline")))
        }
        val result = source(repo).load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue((result as PagingSource.LoadResult.Error).throwable is IOException)
    }
}
