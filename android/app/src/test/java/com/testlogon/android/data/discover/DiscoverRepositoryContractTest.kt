package com.testlogon.android.data.discover

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.Dispatcher
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.RecordedRequest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-182 — contract tests for [DiscoverRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 * Verifies the per-section fan-out decoding, snake_case mapping, partial-failure tolerance, and the
 * total-failure classification (network -> NetworkError).
 */
class DiscoverRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    // Plain codegen Moshi (no KotlinJsonAdapterFactory) — DTOs use @JsonClass(generateAdapter = true).
    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): DiscoverRepositoryImpl {
        val api = backend.retrofit(moshi).create(DiscoverApi::class.java)
        return DiscoverRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    /** Routes by path so the three concurrent calls each get the right body regardless of order. */
    private fun routing(
        suggested: () -> MockResponse,
        trending: () -> MockResponse,
        tags: () -> MockResponse,
    ): Dispatcher = object : Dispatcher() {
        override fun dispatch(request: RecordedRequest): MockResponse {
            val path = request.requestUrl?.encodedPath.orEmpty()
            return when {
                path.endsWith("/ui/discover/suggested") -> suggested()
                path.endsWith("/ui/discover/trending") -> trending()
                path.endsWith("/ui/discover/trending-tags") -> tags()
                else -> MockResponse().setResponseCode(404)
            }
        }
    }

    @Test
    fun getDiscover_decodesAllSections_andMapsSnakeCase() = runTest {
        backend.server.dispatcher = routing(
            suggested = {
                Fixtures.okBody(
                    """{"items":[{"user_id":"u_ava","display_name":"Ava","profile_photo_url":"http://h/a.jpg",
                       "description":"Daily drops","follower_count":1280,"is_following":false}],
                       "next_cursor":"c1","total_estimate":42}""",
                )
            },
            trending = {
                Fixtures.okBody(
                    """{"items":[{"user_id":"u_max","display_name":"Max","follower_count":50}],"total_estimate":1}""",
                )
            },
            tags = {
                Fixtures.okBody(
                    """{"tags":[{"tag":"art","count":99,"last_used_at":"2026-06-01T00:00:00Z"},
                       {"tag":"music","count":12,"last_used_at":"2026-06-01T00:00:00Z"}]}""",
                )
            },
        )

        val result = repo().getDiscover()
        assertTrue(result is ApiResult.Success)
        val c = (result as ApiResult.Success).data
        assertEquals(1, c.suggested.size)
        assertEquals("u_ava", c.suggested[0].userId)
        assertEquals("Ava", c.suggested[0].displayName)
        assertEquals("http://h/a.jpg", c.suggested[0].profilePhotoUrl)
        assertEquals(1280, c.suggested[0].followerCount)
        assertEquals(1, c.trendingCreators.size)
        assertEquals(listOf("art", "music"), c.trendingTags.map { it.tag })
    }

    @Test
    fun getDiscover_partialFailure_oneSectionSucceeds_emitsSuccess() = runTest {
        backend.server.dispatcher = routing(
            suggested = {
                Fixtures.okBody("""{"items":[{"user_id":"u1","display_name":"A","follower_count":1}]}""")
            },
            trending = { Fixtures.error(""""server error"""", 500) },
            tags = { Fixtures.error(""""server error"""", 500) },
        )

        val result = repo().getDiscover()
        assertTrue(result is ApiResult.Success)
        val c = (result as ApiResult.Success).data
        assertEquals(1, c.suggested.size)
        assertTrue(c.trendingCreators.isEmpty())
        assertTrue(c.trendingTags.isEmpty())
    }

    @Test
    fun getDiscover_allFail_network_emitsNetworkError_andCachesLastSuccess() = runTest {
        // First: a success so the singleton cache is populated.
        backend.server.dispatcher = routing(
            suggested = { Fixtures.okBody("""{"items":[{"user_id":"u1","display_name":"A","follower_count":1}]}""") },
            trending = { Fixtures.okBody("""{"items":[]}""") },
            tags = { Fixtures.okBody("""{"tags":[]}""") },
        )
        val repo = repo()
        assertTrue(repo.getDiscover() is ApiResult.Success)
        assertEquals("u1", repo.cached()?.suggested?.first()?.userId)

        // Then: every section times out -> NetworkError, but the cache survives.
        backend.server.dispatcher = routing(
            suggested = { Fixtures.timeout() },
            trending = { Fixtures.timeout() },
            tags = { Fixtures.timeout() },
        )
        val result = repo.getDiscover()
        assertTrue(result is ApiResult.NetworkError)
        assertEquals("u1", repo.cached()?.suggested?.first()?.userId)
    }

    @Test
    fun getDiscover_allEmpty_emitsSuccessWithEmptyContent() = runTest {
        backend.server.dispatcher = routing(
            suggested = { Fixtures.okBody("""{"items":[]}""") },
            trending = { Fixtures.okBody("""{"items":[]}""") },
            tags = { Fixtures.okBody("""{"tags":[]}""") },
        )
        val result = repo().getDiscover()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun clearCache_drops_lastSuccess() = runTest {
        backend.server.dispatcher = routing(
            suggested = { Fixtures.okBody("""{"items":[{"user_id":"u1","display_name":"A","follower_count":1}]}""") },
            trending = { Fixtures.okBody("""{"items":[]}""") },
            tags = { Fixtures.okBody("""{"tags":[]}""") },
        )
        val repo = repo()
        repo.getDiscover()
        repo.clearCache()
        assertEquals(null, repo.cached())
    }
}
