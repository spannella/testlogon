package com.testlogon.android.data.gallery

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
 * AND-201 — contract tests for [GalleryRepositoryImpl]. Verifies the browse/search/categories paths and
 * envelopes, DTO->domain mapping (nullable thumbnail/duration, epoch created_at, default counts,
 * required-field-missing item dropped), the `cursor` next-page field, and 422 mapping.
 */
class GalleryRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): GalleryRepositoryImpl {
        val api = backend.retrofit(moshi).create(GalleryApi::class.java)
        return GalleryRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun browse_parsesPage_mapsItems_dropsInvalid() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"videos":[
                   {"video_id":"v1","title":"Sunset","owner_user_id":"o1","thumbnail_url":"http://h/1.jpg","duration_seconds":154.0,"view_count":1203,"like_count":88,"comment_count":12,"price_cents":0,"created_at":1717091525},
                   {"video_id":"v2","title":"NoThumb","owner_user_id":"o1","price_cents":500,"created_at":1717091600},
                   {"video_id":"","title":"Broken","owner_user_id":"o1"}
                ],"categories":[{"slug":"travel","label":"Travel"}],"cursor":"c2"}""",
            ),
        )
        val result = repo().browse(category = "travel", cursor = null)
        assertTrue(result is ApiResult.Success)
        val page = (result as ApiResult.Success).data
        assertEquals(2, page.videos.size) // the blank-id item is dropped
        assertEquals("v1", page.videos[0].videoId)
        assertEquals(154.0, page.videos[0].durationSeconds!!, 0.0001)
        assertEquals(1717091525L, page.videos[0].createdAt)
        assertNull(page.videos[1].thumbnailUrl)
        assertTrue(page.videos[1].isPpv)
        assertEquals("c2", page.cursor)
        assertEquals("Travel", page.categories.single().label)

        val req = backend.takeRequest()
        assertEquals("/ui/videos/gallery", req.requestUrl?.encodedPath)
        assertEquals("travel", req.requestUrl?.queryParameter("category"))
    }

    @Test
    fun browse_lastPage_cursorNull() = runTest {
        backend.enqueue(Fixtures.okBody("""{"videos":[],"categories":[],"cursor":null}"""))
        val page = (repo().browse(null, "c1") as ApiResult.Success).data
        assertTrue(page.videos.isEmpty())
        assertNull(page.cursor)
        assertEquals("c1", backend.takeRequest().requestUrl?.queryParameter("cursor"))
    }

    @Test
    fun search_path_andQuery() = runTest {
        backend.enqueue(Fixtures.okBody("""{"videos":[{"video_id":"v1","title":"Bay","owner_user_id":"o1"}],"cursor":null}"""))
        val page = (repo().search(query = "bay", cursor = null) as ApiResult.Success).data
        assertEquals("v1", page.videos.single().videoId)
        val req = backend.takeRequest()
        assertEquals("/ui/videos/gallery/search", req.requestUrl?.encodedPath)
        assertEquals("bay", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun categories_parsesList() = runTest {
        backend.enqueue(Fixtures.okBody("""{"categories":[{"slug":"a","label":"A"},{"slug":"b","label":"B"}]}"""))
        val cats = (repo().categories() as ApiResult.Success).data
        assertEquals(2, cats.size)
        assertEquals("a", cats[0].slug)
        assertEquals("/ui/videos/gallery/categories", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun browse_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","q"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().browse(null, null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
