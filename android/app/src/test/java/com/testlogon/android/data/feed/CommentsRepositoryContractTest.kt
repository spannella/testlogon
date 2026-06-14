package com.testlogon.android.data.feed

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-174 — contract tests for [CommentsRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 * Verifies the list envelope { items, next_cursor }, DTO mapping (comment_id/author_id/etc),
 * client-derived canDelete (author_id == current user), add returns 200 (not 201), delete 200, and
 * error folding.
 */
class CommentsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(userSub: String? = "u_me"): CommentsRepositoryImpl {
        val api = backend.retrofit(moshi).create(EngagementApi::class.java)
        return CommentsRepositoryImpl(api, ApiErrorParser(moshi), FakeAuthStateStore(userSub))
    }

    @Test
    fun getComments_decodesPage_mapsDomain_derivesCanDelete() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"items":[
                  {"comment_id":"c1","post_id":"p1","parent_comment_id":null,"author_id":"u_me",
                   "body":"mine","created_at":"2026-06-05T12:00:00Z","deleted":false},
                  {"comment_id":"c2","post_id":"p1","author_id":"u_other",
                   "body":null,"created_at":"2026-06-05T11:00:00Z","deleted":true}
                ],"next_cursor":"NEXT"}
                """.trimIndent(),
            ),
        )
        val result = repo("u_me").getComments("p1", cursor = null, limit = 20)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.items.size)
        assertEquals("NEXT", page.nextCursor)

        val mine = page.items[0]
        assertEquals("c1", mine.id)
        assertTrue(mine.canDelete) // author_id == current user
        assertEquals("mine", mine.body)

        val other = page.items[1]
        assertEquals("", other.body) // null body -> empty string
        assertTrue(other.deleted)
        assertTrue(!other.canDelete) // deleted + not mine

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/posts/p1/comments", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getComments_endOfPagination_nullCursor() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"next_cursor":null}"""))
        val result = repo().getComments("p1", cursor = "c2", limit = 20)
        assertTrue(result is ApiResult.Success)
        assertNull((result as ApiResult.Success).data.nextCursor)
    }

    @Test
    fun addComment_posts200_mapsDomain_sendsBody() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"comment_id":"new1","post_id":"p1","author_id":"u_me","body":"hi",
                   "created_at":"2026-06-05T12:00:00Z"}""",
            ),
        )
        val result = repo("u_me").addComment("p1", "hi", parentId = null)
        assertTrue(result is ApiResult.Success)
        assertEquals("new1", (result as ApiResult.Success).data.id)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/posts/p1/comments", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"body\":\"hi\""))
        // Top-level comment: parent is either omitted (Moshi drops nulls) or explicitly null.
        assertTrue(!body.contains("parent_comment_id") || body.contains("\"parent_comment_id\":null"))
    }

    @Test
    fun addComment_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"Comment is too long","type":"value_error"}]""", 422))
        val result = repo().addComment("p1", "x", null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun deleteComment_200_success() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().deleteComment("p1", "c1")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/posts/p1/comments/c1", req.requestUrl?.encodedPath)
    }

    @Test
    fun deleteComment_403_honored_asFailure() = runTest {
        backend.enqueue(Fixtures.error(""""forbidden"""", 403))
        val result = repo().deleteComment("p1", "c1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }
}
