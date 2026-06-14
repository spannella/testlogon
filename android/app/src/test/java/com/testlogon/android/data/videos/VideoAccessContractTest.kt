package com.testlogon.android.data.videos

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-197 / AND-198 — contract tests for the per-video access check (GET ui/videos/{video_id}/access ->
 * VodAccessOut). Verifies the real wire shape (entitled + reason + flat flags, no nested pricing),
 * unknown-field tolerance, the request line (no user_sub query), and the 404 / 403-geo_blocked / 422
 * error mapping.
 */
class VideoAccessContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): VideosRepositoryImpl {
        val api = backend.retrofit(moshi).create(VideosApi::class.java)
        return VideosRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun checkAccess_decodesRealVodAccessOut_andRequestLine() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"entitled":false,"reason":"purchase_required","access_mode":"ppv","price_cents":499,
                   "purchase_type":"permanent","purchase_available":true,"subscription_available":false,
                   "subscription_upsell":false,"expires_at":null,"views_remaining":-1,"ads_enabled":false,
                   "download_allowed":false}""",
            ),
        )
        val result = repo().checkAccess("vid_1")
        assertTrue(result is ApiResult.Success)
        val access = (result as ApiResult.Success).data
        assertFalse(access.entitled)
        assertEquals("purchase_required", access.reason)
        assertEquals("ppv", access.accessMode)
        assertEquals(499, access.priceCents)
        assertTrue(access.purchaseAvailable)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/videos/vid_1/access", req.requestUrl?.encodedPath)
        // Identity is derived from the session server-side; the client must not send user_sub.
        assertNull(req.requestUrl?.queryParameter("user_sub"))
    }

    @Test
    fun checkAccess_404_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"Not found\"", 404))
        val result = repo().checkAccess("missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(404, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun checkAccess_403_geoBlocked_carriesCode() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"geo_blocked","message":"Not available in your region"}""", 403))
        val result = repo().checkAccess("vid_1")
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(403, error.status)
        assertEquals("geo_blocked", error.code)
    }

    @Test
    fun checkAccess_422_validationError_mapsToFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["path","video_id"],"msg":"invalid id","type":"value_error"}]""", 422),
        )
        val result = repo().checkAccess("vid_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
