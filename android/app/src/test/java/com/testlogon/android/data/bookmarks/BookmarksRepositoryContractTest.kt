package com.testlogon.android.data.bookmarks

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-096 — contract tests for [BookmarksRepositoryImpl] against MockWebServer. Verifies the AND-092
 * wire contract: list envelope `bookmarks` (not `items`), content_preview mapping, cursor paging,
 * DELETE path + 200 / tolerated-404, and POST (resave).
 */
class BookmarksRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BookmarksRepositoryImpl {
        val api = backend.retrofit(moshi).create(BookmarksApi::class.java)
        return BookmarksRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun page_decodesBookmarksEnvelope_mapsPreview_andSendsLimit() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"bookmarks":[
                  {"content_type":"post","content_id":"post_1","collection_id":"default",
                   "created_at":"2026-06-05T09:31:44Z",
                   "content_preview":{"author_display_name":"Sunset Studio","body_snippet":"BTS...","image_url":"https://x/t.jpg"}},
                  {"content_type":"video","content_id":"vid_2","collection_id":"default","created_at":null}
                ],"next_cursor":"c2","total_count":137}
                """.trimIndent(),
            ),
        )
        val result = repo().page(cursor = null, limit = 20)

        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.items.size)
        assertEquals("c2", page.nextCursor)
        assertEquals(137, page.totalCount)
        assertEquals("Sunset Studio", page.items[0].title) // from content_preview
        assertEquals("https://x/t.jpg", page.items[0].thumbnailUrl)
        assertEquals("post/post_1", page.items[0].key)
        assertNull(page.items[1].title) // missing preview -> null, no crash
        assertNull(page.items[1].savedAtIso)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/bookmarks", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun unsave_success_hitsCompositePath() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().unsave("post", "post_1")

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/bookmarks/post/post_1", req.requestUrl?.encodedPath)
    }

    @Test
    fun unsave_404_toleratedAsAlreadyRemoved() = runTest {
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val result = repo().unsave("post", "ghost")
        assertTrue(result is ApiResult.Success) // 404 -> success (row stays gone)
    }

    @Test
    fun unsave_500_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().unsave("post", "post_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun resave_postsCreateBody() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}""", code = 201))
        val bookmark = Bookmark(
            contentType = "post",
            contentId = "post_1",
            collectionId = "default",
            title = null,
            subtitle = null,
            thumbnailUrl = null,
            savedAtIso = null,
        )
        val result = repo().resave(bookmark)

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/bookmarks", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("post", body["content_type"])
        assertEquals("post_1", body["content_id"])
    }
}
