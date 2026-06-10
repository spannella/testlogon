package com.testlogon.android.data.bookmarks

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-176 — contract + optimistic-toggle tests for [FeedBookmarkRepositoryImpl] against MockWebServer.
 * Verifies the real /ui/bookmarks contract (POST add, DELETE composite path, 409/404 idempotency,
 * status hydration), the optimistic Room flip, and rollback on hard failure.
 */
class FeedBookmarkRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val dao = FakeBookmarkStateDao()

    private fun repo(): FeedBookmarkRepositoryImpl {
        val api = backend.retrofit(moshi).create(BookmarksApi::class.java)
        return FeedBookmarkRepositoryImpl(api = api, dao = dao, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun setBookmarked_true_optimisticallySaves_thenPostsCreate() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 201))
        val r = repo().setBookmarked("post_1", true)

        assertTrue(r is ApiResult.Success)
        assertTrue(dao.isBookmarked("post", "post_1").first()) // saved
        assertFalse(dao.snapshot().first().pending) // pending cleared on ack

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/bookmarks", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("post", body["content_type"])
        assertEquals("post_1", body["content_id"])
    }

    @Test
    fun setBookmarked_false_hitsCompositeDeletePath() = runTest {
        // Seed an existing saved row.
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 201))
        repo().setBookmarked("post_1", true)
        backend.takeRequest()

        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val r = repo().setBookmarked("post_1", false)

        assertTrue(r is ApiResult.Success)
        assertFalse(dao.isBookmarked("post", "post_1").first())
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/bookmarks/post/post_1", req.requestUrl?.encodedPath)
    }

    @Test
    fun setBookmarked_add409_treatedAsSuccess() = runTest {
        backend.enqueue(Fixtures.error("\"already bookmarked\"", 409))
        val r = repo().setBookmarked("post_1", true)
        assertTrue(r is ApiResult.Success) // 409 -> desired state already holds
        assertTrue(dao.isBookmarked("post", "post_1").first())
    }

    @Test
    fun setBookmarked_remove404_treatedAsSuccess() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 201))
        repo().setBookmarked("post_1", true)
        backend.takeRequest()

        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().setBookmarked("post_1", false)
        assertTrue(r is ApiResult.Success) // 404 -> already removed
        assertFalse(dao.isBookmarked("post", "post_1").first())
    }

    @Test
    fun setBookmarked_addFailure_rollsBack() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val r = repo().setBookmarked("post_1", true)
        assertTrue(r is ApiResult.Failure)
        assertEquals(500, (r as ApiResult.Failure).error.status)
        assertFalse(dao.isBookmarked("post", "post_1").first()) // rolled back, no orphan row
    }

    @Test
    fun setBookmarked_removeFailure_restoresRow() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 201))
        repo().setBookmarked("post_1", true)
        backend.takeRequest()

        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val r = repo().setBookmarked("post_1", false)
        assertTrue(r is ApiResult.Failure)
        assertTrue(dao.isBookmarked("post", "post_1").first()) // restored on rollback
    }

    @Test
    fun hydrate_seedsSavedIdsFromStatus() = runTest {
        backend.enqueue(Fixtures.okBody("""{"statuses":{"post_1":true,"post_2":false}}"""))
        val r = repo().hydrate(listOf("post_1", "post_2"))
        assertTrue(r is ApiResult.Success)
        assertTrue(dao.isBookmarked("post", "post_1").first())
        assertFalse(dao.isBookmarked("post", "post_2").first())

        val req = backend.takeRequest()
        assertEquals("/ui/bookmarks/status", req.requestUrl?.encodedPath)
        assertEquals("post_1,post_2", req.requestUrl?.queryParameter("ids"))
    }
}
