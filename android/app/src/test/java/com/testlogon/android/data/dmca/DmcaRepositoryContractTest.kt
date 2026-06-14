package com.testlogon.android.data.dmca

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-384 - contract tests for [DefaultDmcaRepository] against MockWebServer
 * (TC-AND-384-01..06). Asserts the REAL wire contract for POST v1/dmca/claims:
 *  - exact snake_case body keys, the CSRF header on the mutating verb,
 *  - 201 -> ApiResult.Success with claim_id + integer epoch created_at,
 *  - 422 -> Failure that preserves the body for per-field loc-tail mapping,
 *  - 429 / 5xx / transport -> the right Failure / NetworkError,
 *  - ZERO automatic retries on the non-idempotent POST (exactly one recorded request).
 */
class DmcaRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun csrfClient(): OkHttpClient {
        val csrf = Interceptor { chain ->
            val req = chain.request()
            val out = if (req.method in MUTATING) {
                req.newBuilder().header("X-CSRF-Token", CSRF).build()
            } else {
                req
            }
            chain.proceed(out)
        }
        return defaultTestClient().newBuilder().addInterceptor(csrf).build()
    }

    private fun repo(client: OkHttpClient = csrfClient()): DefaultDmcaRepository {
        val rf = backend.retrofit(moshi, client)
        return DefaultDmcaRepository(
            api = rf.create(DmcaApi::class.java),
            draftStore = FakeDmcaDraftStore(),
            errorParser = ApiErrorParser(moshi),
        )
    }

    private fun request() = DmcaClaimRequest(
        claimantName = "Jane Doe",
        claimantEmail = "jane@example.com",
        claimantAddress = "123 Main St, Springfield, IL 62701, USA",
        claimantPhone = null,
        contentUrl = "https://testlogon.app/p/abc123",
        contentType = DmcaContentType.FEED_POST,
        contentId = "abc123",
        originalWorkDescription = "Original photograph 'Sunset #4', registration VA-1-234-567",
        swornStatement = true,
        goodFaithBelief = true,
        signature = "Jane Doe",
    )

    // TC-AND-384-01
    @Test
    fun submit_postsCorrectPathAndBody_withCsrf() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"claim_id":"dmca_x","status":"received","content_removed":false,
                   "strike_number":1,"created_at":1749132069}""",
                code = 201,
            ),
        )

        val result = repo().submit(request())
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/v1/dmca/claims", req.requestUrl?.encodedPath)
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        val body = req.bodyJson()
        assertEquals("Jane Doe", body["claimant_name"])
        assertEquals("jane@example.com", body["claimant_email"])
        assertEquals("123 Main St, Springfield, IL 62701, USA", body["claimant_address"])
        assertEquals("https://testlogon.app/p/abc123", body["content_url"])
        assertEquals("feed_post", body["content_type"])
        assertEquals("abc123", body["content_id"])
        assertEquals(
            "Original photograph 'Sunset #4', registration VA-1-234-567",
            body["original_work_description"],
        )
        assertEquals(true, body["sworn_statement"])
        assertEquals(true, body["good_faith_belief"])
        assertEquals("Jane Doe", body["signature"])
        // A null optional phone is OMITTED by Moshi codegen (default does not serialize nulls); the
        // backend treats an absent claimant_phone as its default "". Either way the value is null here.
        assertNull(body["claimant_phone"])
    }

    // TC-AND-384-02
    @Test
    fun submit_201_parsesClaimIdAndIntegerEpochCreatedAt() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"claim_id":"dmca_x","status":"received","content_removed":true,
                   "strike_number":2,"created_at":1749132069}""",
                code = 201,
            ),
        )
        val result = repo().submit(request())
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals("dmca_x", data.claimId)
        assertEquals("received", data.status)
        assertEquals(true, data.contentRemoved)
        assertEquals(2, data.strikeNumber)
        assertEquals(1749132069L, data.createdAt)
    }

    // TC-AND-384-03
    @Test
    fun submit_422_preservesBodyForFieldMapping() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","claimant_email"],"msg":"value is not a valid email address","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().submit(request())
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(422, error.status)
        // The 373 loc-tail mapper resolves the per-field message off the preserved raw body.
        assertEquals(
            "value is not a valid email address",
            ApiErrorParser(moshi).fieldErrorForLocTail(error, "claimant_email"),
        )
    }

    // TC-AND-384-04 (rate limited)
    @Test
    fun submit_429_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"slow down\"", 429))
        val result = repo().submit(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals(429, (result as ApiResult.Failure).error.status)
    }

    // TC-AND-384-04 (server error)
    @Test
    fun submit_500_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        val result = repo().submit(request())
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
    }

    // TC-AND-384-04 (transport) + TC-AND-384-06 (no retry)
    @Test
    fun submit_transportFailure_mapsToNetworkError_withSingleRequest() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().submit(request())
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
        // Exactly one request was made; the non-idempotent POST is never auto-retried.
        assertEquals(1, backend.requestCount)
    }

    // TC-AND-384-06 - a 5xx is NOT auto-retried either (single recorded request).
    @Test
    fun submit_serverError_isNotAutoRetried() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 503))
        repo().submit(request())
        assertEquals(1, backend.requestCount)
    }

    private companion object {
        const val CSRF = "csrf-tok-384"
        val MUTATING = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
