package com.testlogon.android.data.discover

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-184 — contract tests for [RecommendationsRepositoryImpl]. Verifies path/params, ForYouResponse
 * decoding (video_id / thumbnail_url / recommendation_reason), the trending-fallback source, defensive
 * drop of a malformed (blank video_id) item, stale cache after a transient failure, and 422 mapping.
 */
class RecommendationsRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): RecommendationsRepositoryImpl {
        val api = backend.retrofit(moshi).create(DiscoverApi::class.java)
        return RecommendationsRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getRecommendations_decodes_andMapsRealFieldNames() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"videos":[
                   {"video_id":"med_1","title":"Sample","thumbnail_url":"http://h/t.jpg",
                    "recommendation_reason":"Because you watched X"}
                ],"next_cursor":null,"source":"for_you"}""",
            ),
        )
        val result = repo().getRecommendations()
        assertTrue(result is ApiResult.Success)
        val recs = (result as ApiResult.Success).data
        val item = recs.items.single()
        assertEquals("med_1", item.id)
        assertEquals("http://h/t.jpg", item.posterUrl)
        assertEquals("Because you watched X", item.reason)
        assertEquals(false, recs.isTrendingFallback)

        val req = backend.takeRequest()
        assertEquals("/ui/videos/gallery/for-you", req.requestUrl?.encodedPath)
        assertEquals("24", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getRecommendations_trendingFallback_flagged() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"videos":[{"video_id":"v1","title":"T"}],"source":"trending_fallback"}"""),
        )
        val result = repo().getRecommendations()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isTrendingFallback)
    }

    @Test
    fun getRecommendations_dropsMalformedItem_keepsValid() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"videos":[{"video_id":"","title":"bad"},{"video_id":"ok","title":"good"}],"source":"for_you"}""",
            ),
        )
        val result = repo().getRecommendations()
        assertTrue(result is ApiResult.Success)
        val items = (result as ApiResult.Success).data.items
        assertEquals(1, items.size)
        assertEquals("ok", items.single().id)
    }

    @Test
    fun getRecommendations_stale_cacheSurvivesTransientFailure() = runTest {
        val repo = repo()
        backend.enqueue(Fixtures.okBody("""{"videos":[{"video_id":"v1","title":"T"}],"source":"for_you"}"""))
        assertTrue(repo.getRecommendations() is ApiResult.Success)
        assertEquals("v1", repo.cached()?.items?.single()?.id)

        backend.enqueue(Fixtures.error(""""server error"""", 500))
        val failed = repo.getRecommendations()
        assertTrue(failed is ApiResult.Failure)
        assertEquals("v1", repo.cached()?.items?.single()?.id) // cache preserved
    }

    @Test
    fun getRecommendations_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","limit"],"msg":"x","type":"value_error"}]""", 422))
        val result = repo().getRecommendations()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
