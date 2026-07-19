package com.testlogon.android.feature.feed

import androidx.paging.PagingSource
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.CommentPage
import com.testlogon.android.data.feed.CommentsRepository
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-174 — [CommentsPagingSource] load + end-of-pagination + error tests. */
class CommentsPagingSourceTest {

    /**
     * P2 — thin repo over the shared [FakeCommentsRepository] whose getComments returns a single canned
     * result (success page or failure), so the paging source's load/end/error branches can be exercised
     * without re-declaring the whole (grown) CommentsRepository surface.
     */
    private class StubRepo(
        private val result: ApiResult<CommentPage>,
    ) : CommentsRepository by FakeCommentsRepository() {
        override suspend fun getComments(postId: String, cursor: String?, limit: Int) = result
    }

    private fun comment(id: String) = FakeCommentsRepository.comment(id = id, postId = "p1")

    @Test
    fun load_success_returnsPage_withNextKey() = runTest {
        val src = CommentsPagingSource(
            StubRepo(ApiResult.Success(CommentPage(listOf(comment("c1")), nextCursor = "NEXT"))),
            "p1",
        )
        val result = src.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Page)
        val page = result as PagingSource.LoadResult.Page
        assertEquals(listOf("c1"), page.data.map { it.id })
        assertNull(page.prevKey)
        assertEquals("NEXT", page.nextKey)
    }

    @Test
    fun load_nullCursor_endOfPagination() = runTest {
        val src = CommentsPagingSource(
            StubRepo(ApiResult.Success(CommentPage(emptyList(), nextCursor = null))),
            "p1",
        )
        val result = src.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertNull((result as PagingSource.LoadResult.Page).nextKey)
    }

    @Test
    fun load_failure_returnsError() = runTest {
        val src = CommentsPagingSource(
            StubRepo(FakeCommentsRepository.failure(500)),
            "p1",
        )
        val result = src.load(PagingSource.LoadParams.Refresh(key = null, loadSize = 20, placeholdersEnabled = false))
        assertTrue(result is PagingSource.LoadResult.Error)
    }
}
