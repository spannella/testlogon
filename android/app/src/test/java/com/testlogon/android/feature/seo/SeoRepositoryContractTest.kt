package com.testlogon.android.feature.seo

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.feature.seo.data.ResourceType
import com.testlogon.android.feature.seo.data.SeoApi
import com.testlogon.android.feature.seo.data.SeoMetadataMapper
import com.testlogon.android.feature.seo.data.SeoRepositoryImpl
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-400 - contract tests for the SEO data layer against MockWebServer (real Retrofit/Moshi). Codegen
 * adapters resolve without the reflection factory; the json_ld Map<String,Any?> uses the built-in map
 * adapter (matches DashboardRepositoryContractTest's plain Moshi.Builder()).
 */
class SeoRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SeoRepositoryImpl {
        val api = backend.retrofit(moshi).create(SeoApi::class.java)
        return SeoRepositoryImpl(
            api = api,
            mapper = SeoMetadataMapper(moshi),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun getSeoMetadata_parsesFullFixtureAndIssuesQueryParams() = runTest {
        backend.enqueue(Fixtures.okBody(FULL_FIXTURE))
        val result = repo().metadata(ResourceType.PROFILE, "abc123")
        assertTrue(result is ApiResult.Success)
        val meta = (result as ApiResult.Success).data
        assertEquals("My Profile — TestLogon", meta.title)
        assertEquals("https://testlogon.example/u/alice", meta.canonicalUrl)
        assertEquals("TestLogon", meta.siteName)
        assertEquals("en_US", meta.locale)
        assertEquals("profile", meta.resourceType)
        // Flat og / twitter maps with prefixed keys.
        assertEquals("My Profile", meta.og["og:title"])
        assertEquals("https://.../og.png", meta.og["og:image"])
        assertEquals("summary_large_image", meta.twitter["twitter:card"])
        assertEquals("https://.../og.png", meta.image)
        // Single json_ld object pretty-printed to a non-blank string.
        assertTrue(meta.jsonLd!!.contains("schema.org"))
        assertFalse(meta.isEmpty)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/seo/metadata", recorded.requestUrl?.encodedPath)
        assertEquals("profile", recorded.requestUrl?.queryParameter("type"))
        assertEquals("abc123", recorded.requestUrl?.queryParameter("id"))
        assertNull(recorded.requestUrl?.queryParameter("secondary_id"))
    }

    @Test
    fun getSeoMetadata_event_sendsSecondaryIdAndMapsSnakeCase() = runTest {
        backend.enqueue(Fixtures.okBody(FULL_FIXTURE))
        repo().metadata(ResourceType.EVENT, "cal1", "evt9")
        val recorded = backend.takeRequest()
        assertEquals("/seo/metadata", recorded.requestUrl?.encodedPath)
        assertEquals("event", recorded.requestUrl?.queryParameter("type"))
        assertEquals("cal1", recorded.requestUrl?.queryParameter("id"))
        assertEquals("evt9", recorded.requestUrl?.queryParameter("secondary_id"))
    }

    @Test
    fun getSeoMetadataForPath_issuesPathQueryParam() = runTest {
        backend.enqueue(Fixtures.okBody(FULL_FIXTURE))
        repo().metadataForPath("/u/alice")
        val recorded = backend.takeRequest()
        assertEquals("/seo/metadata", recorded.requestUrl?.encodedPath)
        assertEquals("/u/alice", recorded.requestUrl?.queryParameter("path"))
        assertNull(recorded.requestUrl?.queryParameter("type"))
        assertNull(recorded.requestUrl?.queryParameter("id"))
    }

    @Test
    fun availableFalse_mapsToEmptyDomain() = runTest {
        backend.enqueue(Fixtures.okBody("""{"resource_type":"post","available":false,"title":"Generic"}"""))
        val result = repo().metadata(ResourceType.POST, "p1")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun ignoresUnknownKeys() = runTest {
        backend.enqueue(Fixtures.okBody("""{"available":true,"title":"T","unknown_field":42}"""))
        val result = repo().metadata(ResourceType.VIDEO, "v1")
        assertTrue(result is ApiResult.Success)
        assertEquals("T", (result as ApiResult.Success).data.title)
    }

    @Test
    fun validationError_422_mapsToFailure() = runTest {
        // Fixtures.error wraps the value in {"detail": ...}; pass only the validation array.
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["query","type"],"msg":"field required","type":"missing"}]""",
                422,
            ),
        )
        val result = repo().metadata(ResourceType.PROFILE, "")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertTrue(result.error.message.contains("field required"))
    }

    @Test
    fun serverError_500_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().metadata(ResourceType.PROFILE, "x")
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun transportFailure_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        val result = repo().metadata(ResourceType.PROFILE, "x")
        assertTrue(result is ApiResult.NetworkError)
    }

    private companion object {
        const val FULL_FIXTURE = """
            {
              "resource_type": "profile",
              "resource_id": "abc123",
              "available": true,
              "title": "My Profile — TestLogon",
              "description": "Latest content from My Profile.",
              "canonical_url": "https://testlogon.example/u/alice",
              "site_name": "TestLogon",
              "locale": "en_US",
              "og": {
                "og:title": "My Profile",
                "og:description": "Latest content from My Profile.",
                "og:type": "profile",
                "og:image": "https://.../og.png"
              },
              "twitter": {
                "twitter:card": "summary_large_image",
                "twitter:title": "My Profile",
                "twitter:image": "https://.../og.png"
              },
              "image": "https://.../og.png",
              "json_ld": { "@context": "https://schema.org", "@type": "ProfilePage" }
            }
        """
    }
}
