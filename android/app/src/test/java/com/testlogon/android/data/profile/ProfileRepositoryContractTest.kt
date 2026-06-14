package com.testlogon.android.data.profile

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.profile.ProfilePatch
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.mockwebserver.MockResponse
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-070 / AND-076 — contract tests for the profile data layer over MockWebServer (real Retrofit/Moshi). */
class ProfileRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ProfileRepositoryImpl {
        val api = backend.retrofit(moshi).create(ProfileApi::class.java)
        return ProfileRepositoryImpl(
            api = api,
            uploader = ProfileMediaUploaderImpl(api),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun getOwnProfile_unwrapsEnvelope_andMaps() = runTest {
        backend.enqueue(Fixtures.okBody(OWN_BODY))
        val result = repo().getOwnProfile()
        assertTrue(result is ApiResult.Success)
        val p = (result as ApiResult.Success).data
        assertEquals("Sean", p.displayName)
        assertEquals("spannella@gmail.com", p.displayedEmail)
        assertTrue(p.languages.isEmpty())

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/profile", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun getOwnProfile_populatesCache() = runTest {
        backend.enqueue(Fixtures.okBody(OWN_BODY))
        val r = repo()
        r.getOwnProfile()
        assertTrue(r.cachedOwnProfile() != null)
    }

    @Test
    fun getPublicProfile_found_mapsAndHitsCorrectPath() = runTest {
        backend.enqueue(Fixtures.okBody(PUBLIC_BODY))
        val result = repo().getPublicProfile("ada")
        assertTrue(result is ProfileResult.Found)
        val p = (result as ProfileResult.Found).profile
        assertEquals("Ada Lovelace", p.displayName)
        assertEquals(1280, p.followerCount)
        assertEquals(1735992000L, p.createdAtEpochSeconds)
        assertEquals("/ui/profile/public/ada", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun getPublicProfile_blankIdentifier_notFound_withoutNetworkCall() = runTest {
        val result = repo().getPublicProfile("   ")
        assertTrue(result is ProfileResult.NotFound)
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun getPublicProfile_404_mapsToNotFound() = runTest {
        backend.enqueue(Fixtures.error("\"Profile not available\"", 404))
        assertTrue(repo().getPublicProfile("ghost") is ProfileResult.NotFound)
    }

    @Test
    fun getPublicProfile_429_mapsToRateLimited_withRetryAfterHeader() = runTest {
        backend.enqueue(
            MockResponse()
                .setResponseCode(429)
                .setHeader("Content-Type", "application/json")
                .setHeader("Retry-After", "30")
                .setBody("""{"detail":"Too many profile lookups."}"""),
        )
        val result = repo().getPublicProfile("ada")
        assertTrue(result is ProfileResult.RateLimited)
        assertEquals(30L, (result as ProfileResult.RateLimited).retryAfterSeconds)
    }

    @Test
    fun getPublicProfile_429_retryAfterFromBody() = runTest {
        backend.enqueue(Fixtures.error("""{"retry_after_seconds":45}""", 429))
        val result = repo().getPublicProfile("ada")
        assertTrue(result is ProfileResult.RateLimited)
        assertEquals(45L, (result as ProfileResult.RateLimited).retryAfterSeconds)
    }

    @Test
    fun getPublicProfile_transportFailure_mapsToOffline() = runTest {
        backend.enqueue(Fixtures.disconnect())
        assertTrue(repo().getPublicProfile("ada") is ProfileResult.Offline)
    }

    @Test
    fun updateProfile_patches_unwrapsEnvelope_andWritesThroughCache() = runTest {
        backend.enqueue(Fixtures.okBody("""{"profile":{"display_name":"New Name","description":"Bio"}}"""))
        val r = repo()
        val result = r.updateProfile(ProfilePatch(displayName = "New Name", description = "Bio"))
        assertTrue(result is ApiResult.Success)
        assertEquals("New Name", (result as ApiResult.Success).data.displayName)
        assertEquals("New Name", r.cachedOwnProfile()?.displayName)

        val recorded = backend.takeRequest()
        assertEquals("PATCH", recorded.method)
        assertEquals("/ui/profile", recorded.requestUrl?.encodedPath)
        val body = recorded.body.readUtf8()
        assertTrue(body.contains("\"display_name\":\"New Name\""))
        assertTrue(body.contains("\"description\":\"Bio\""))
        // location/title not sent (partial update).
        assertTrue(!body.contains("location"))
    }

    @Test
    fun updateProfile_422_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","display_name"],"msg":"too long","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().updateProfile(ProfilePatch(displayName = "x"))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun uploadPhoto_postsMultipart_toCorrectPath_andParsesResponse() = runTest {
        backend.enqueue(Fixtures.okBody("""{"profile":{"profile_photo_url":"https://x/new.png"},"url":"https://x/new.png"}"""))
        val result = repo().uploadPhoto(
            MediaKind.AVATAR,
            ProfileMediaUploader.PreparedUpload(bytes = byteArrayOf(1, 2, 3)),
        )
        assertTrue(result is ApiResult.Success)
        assertEquals("https://x/new.png", (result as ApiResult.Success).data.url)

        val recorded = backend.takeRequest()
        assertEquals("POST", recorded.method)
        assertEquals("/ui/profile/photos/profile/upload", recorded.requestUrl?.encodedPath)
        assertTrue(recorded.getHeader("Content-Type")?.startsWith("multipart/form-data") == true)
        assertTrue(recorded.body.readUtf8().contains("name=\"file\""))
    }

    @Test
    fun publicProfile_identifier_encodesAsSingleSegment() = runTest {
        backend.enqueue(Fixtures.okBody(PUBLIC_BODY))
        repo().getPublicProfile("a b/c")
        assertEquals("/ui/profile/public/a%20b%2Fc", backend.takeRequest().requestUrl?.encodedPath)
    }

    private companion object {
        const val OWN_BODY = """
            {
              "profile": {
                "display_name": "Sean",
                "first_name": "Sean",
                "last_name": "Pannella",
                "location": "Pittsburgh, PA",
                "displayed_email": "spannella@gmail.com",
                "languages": []
              }
            }
        """

        const val PUBLIC_BODY = """
            {
              "user_id": "usr_123",
              "identifier": "ada",
              "canonical_identifier": "ada",
              "display_name": "Ada Lovelace",
              "description": "First programmer.",
              "follower_count": 1280,
              "following_count": 73,
              "post_count": 211,
              "is_following": false,
              "is_followed_by": false,
              "is_mutual": false,
              "has_subscription_plans": true,
              "created_at": 1735992000,
              "discoverability": "public"
            }
        """
    }
}
