package com.testlogon.android.data.vod

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
 * AND-191 — contract tests for [VodRepositoryImpl] against MockWebServer. Verifies endpoint selection
 * by filter (public / gallery / search), paths/params, both envelopes, cursor terminate, and errors.
 */
class VodRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): VodRepositoryImpl {
        val api = backend.retrofit(moshi).create(VodApi::class.java)
        return VodRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun noFilter_hitsPublicCatalog() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"items":[{"video_id":"v1","title":"A","duration_seconds":60.0}],"cursor":"c2"}"""),
        )
        val result = repo().catalogPage(cursor = null, limit = 30)
        assertTrue(result is ApiResult.Success)
        assertEquals("v1", (result as ApiResult.Success).data.items.single().id)
        assertEquals("c2", result.data.cursor)
        val req = backend.takeRequest()
        assertEquals("/ui/videos/public", req.requestUrl?.encodedPath)
        assertEquals("30", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun category_hitsGalleryBrowse() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"videos":[{"video_id":"v2","title":"B"}],"categories":[{"slug":"x","label":"X"}],"cursor":null}"""),
        )
        val result = repo().catalogPage(cursor = null, limit = 30, category = "comedy")
        assertTrue(result is ApiResult.Success)
        assertEquals("v2", (result as ApiResult.Success).data.items.single().id)
        assertNull(result.data.cursor)
        val req = backend.takeRequest()
        assertEquals("/ui/videos/gallery", req.requestUrl?.encodedPath)
        assertEquals("comedy", req.requestUrl?.queryParameter("category"))
    }

    @Test
    fun query_hitsGallerySearch() = runTest {
        backend.enqueue(Fixtures.okBody("""{"videos":[{"video_id":"v3","title":"C"}],"cursor":"n"}"""))
        val result = repo().catalogPage(cursor = null, limit = 30, query = "cats")
        assertTrue(result is ApiResult.Success)
        assertEquals("v3", (result as ApiResult.Success).data.items.single().id)
        val req = backend.takeRequest()
        assertEquals("/ui/videos/gallery/search", req.requestUrl?.encodedPath)
        assertEquals("cats", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun categories_decodes() = runTest {
        backend.enqueue(Fixtures.okBody("""{"categories":[{"slug":"a","label":"A"},{"slug":"b","label":"B"}]}"""))
        val result = repo().categories()
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("a", "b"), (result as ApiResult.Success).data.map { it.slug })
        assertEquals("/ui/videos/gallery/categories", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun catalog_500_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        assertTrue(repo().catalogPage(cursor = null, limit = 30) is ApiResult.Failure)
    }

    @Test
    fun catalog_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        assertTrue(repo().catalogPage(cursor = null, limit = 30) is ApiResult.NetworkError)
    }
}
