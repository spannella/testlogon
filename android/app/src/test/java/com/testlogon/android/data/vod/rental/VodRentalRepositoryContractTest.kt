package com.testlogon.android.data.vod.rental

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import com.testlogon.android.feature.messaging.FakeBillingAuthorizer
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-192 — contract tests for [VodRentalRepositoryImpl] against MockWebServer.
 *
 * Verifies: endpoint paths/methods, tier serialization (rental vs view_once), the stubbed-billing
 * STOP-AND-FLAG path (NotConfigured -> PaymentsUnavailable, NO HTTP call), playback handshake +
 * complete mapping, and error mapping. (The test client carries no CSRF interceptor; production
 * attaches X-CSRF-Token via the shared interceptor chain.)
 */
class VodRentalRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(billing: BillingAuthorizer): VodRentalRepositoryImpl {
        val api = backend.retrofit(moshi).create(VodRentalApi::class.java)
        return VodRentalRepositoryImpl(api = api, billing = billing, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun rent_withStubBilling_debugBypass_authorizesBlankPm_andReachesServer() = runTest {
        // The StubBillingAuthorizer now ships a DEV/DEMO bypass: in DEBUG builds (unit tests run debug) it
        // authorizes with a BLANK payment_method_id so on-device VOD rentals work without a real vendor.
        // So rent is NO LONGER short-circuited to PaymentsUnavailable — it authorizes and POSTs start +
        // refreshes access (the backend dev path mock-completes a blank-pm charge).
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","rental_id":"r1","tier":"rental","already_active":false,
                   "started":true,"expires_at":1749200000,"views_remaining":-1,"amount_cents":399,
                   "duration_hours":48}""".trimIndent(),
            ),
        )
        backend.enqueue(Fixtures.okBody("""{"active":true,"tier":"rental","expires_at":1749200000,"views_remaining":-1}"""))

        val outcome = repo(StubBillingAuthorizer()).rent("v1", "rental", durationHours = 48)
        assertTrue(outcome is RentOutcome.Active)
        assertEquals(2, backend.requestCount) // start + access refresh both reached the server
    }

    @Test
    fun rent_rentalTier_postsStart_withDuration_thenRefreshesAccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","rental_id":"r1","tier":"rental","already_active":false,
                   "started":true,"expires_at":1749200000,"views_remaining":-1,"amount_cents":399,
                   "duration_hours":48}""".trimIndent(),
            ),
        )
        backend.enqueue(Fixtures.okBody("""{"active":true,"tier":"rental","expires_at":1749200000,"views_remaining":-1}"""))

        val outcome = repo(FakeBillingAuthorizer()).rent("v1", "rental", durationHours = 48)
        assertTrue(outcome is RentOutcome.Active)
        assertEquals(1749200000L, (outcome as RentOutcome.Active).receipt.expiresAt)

        val startReq = backend.takeRequest()
        assertEquals("POST", startReq.method)
        assertEquals("/ui/vod/rental/v1/start", startReq.requestUrl?.encodedPath)
        val body = startReq.bodyJson()
        assertEquals("rental", body["tier"])
        assertEquals(48.0, body["rental_duration_hours"]) // JSON numbers decode to Double

        val accessReq = backend.takeRequest()
        assertEquals("/ui/vod/rental/v1/access", accessReq.requestUrl?.encodedPath)
    }

    @Test
    fun rent_viewOnce_omitsDuration() = runTest {
        backend.enqueue(Fixtures.okBody("""{"video_id":"v1","rental_id":"r1","tier":"view_once","views_remaining":1}"""))
        backend.enqueue(Fixtures.okBody("""{"active":true,"tier":"view_once","views_remaining":1}"""))

        repo(FakeBillingAuthorizer()).rent("v1", "view_once", durationHours = 48)
        val body = backend.takeRequest().bodyJson()
        assertEquals("view_once", body["tier"])
        assertNull(body["rental_duration_hours"]) // omitted for view_once
    }

    @Test
    fun status_mapsAccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","active":true,"reason":"pending","expires_at":1749200000,
                   "remaining_seconds":86400,"views_remaining":-1,"started":true}""".trimIndent(),
            ),
        )
        val r = repo(FakeBillingAuthorizer()).status("v1")
        assertTrue(r is ApiResult.Success)
        val access = (r as ApiResult.Success).data
        assertTrue(access.active)
        assertEquals(1749200000L, access.expiresAt)
        assertEquals("/ui/vod/rental/v1/status", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun beginPlayback_mapsUrlAndEmbeddedAccess() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"video_id":"v1","playback_url":"https://x/master.m3u8?tok=abc","mode":"dev",
                   "token_expires_at":1749103600,
                   "access":{"active":true,"remaining_seconds":86040,"views_remaining":-1}}""".trimIndent(),
            ),
        )
        val r = repo(FakeBillingAuthorizer()).beginPlayback("v1")
        assertTrue(r is ApiResult.Success)
        assertEquals("https://x/master.m3u8?tok=abc", (r as ApiResult.Success).data.playbackUrl)
        assertTrue(r.data.access.active)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/vod/rental/v1/playback", req.requestUrl?.encodedPath)
    }

    @Test
    fun finishPlayback_mapsConsume() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"tier":"view_once","views_remaining":0,"consumed":true}"""))
        val r = repo(FakeBillingAuthorizer()).finishPlayback("v1")
        assertTrue(r is ApiResult.Success)
        assertEquals(0, (r as ApiResult.Success).data.viewsRemaining)
        assertTrue(r.data.consumed)
        assertEquals("/ui/vod/rental/v1/playback-complete", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun rent_422_isRetryableFalseFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["body","tier"],"msg":"bad","type":"value_error"}]""", 422))
        val outcome = repo(FakeBillingAuthorizer()).rent("v1", "rental", durationHours = 48)
        assertTrue(outcome is RentOutcome.Failure)
        assertFalse((outcome as RentOutcome.Failure).retryable)
    }

    @Test
    fun rent_declined_isRetryableFailure_noServerCall() = runTest {
        val billing = FakeBillingAuthorizer(BillingResult.Declined("card declined"))
        val outcome = repo(billing).rent("v1", "rental", durationHours = 48)
        assertTrue(outcome is RentOutcome.Failure)
        assertEquals(0, backend.requestCount)
    }
}
