package com.testlogon.android.data.broadcast

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-316 — MockWebServer contract tests for [HostAdRepositoryImpl]. Verifies: getAdConfig decode (incl. a
 * null + an epoch ad_break_started_at); the PATCH partial update sends ONLY the changed fields (omitting the
 * untouched keys) -> 200 decode; triggerAdBreak POSTs no body -> AdBreakOut; endAdBreak POSTs no body and
 * succeeds for both an {ok} ack and an empty 200 (Response<Unit> success-by-isSuccessful); 422 detail mapping.
 * Each request body is read ONCE.
 */
class HostAdRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): HostAdRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return HostAdRepositoryImpl(
            api = retrofit.create(HostAdApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun getAdConfig_decodes_inactiveBreak_nullStartedAt() = runTest {
        backend.enqueue(Fixtures.okBody(CONFIG_INACTIVE_JSON))
        val result = repo().getAdConfig("bcs_1")
        assertTrue(result is ApiResult.Success)
        val config = (result as ApiResult.Success).data
        assertEquals("bcs_1", config.sessionId)
        assertTrue(config.preRollEnabled)
        assertEquals(30, config.midRollDurationSeconds)
        assertEquals(5, config.skipAfterSeconds)
        assertFalse(config.adBreakActive)
        assertNull(config.adBreakStartedAt)
        assertEquals(2, config.totalAdBreaks)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/ad-config", req.requestUrl?.encodedPath)
    }

    @Test
    fun getAdConfig_decodes_activeBreak_epochStartedAt() = runTest {
        backend.enqueue(Fixtures.okBody(CONFIG_ACTIVE_JSON))
        val result = repo().getAdConfig("bcs_1")
        assertTrue(result is ApiResult.Success)
        val config = (result as ApiResult.Success).data
        assertTrue(config.adBreakActive)
        assertEquals(1_700_000_000L, config.adBreakStartedAt)
    }

    @Test
    fun updateAdConfig_patches_onlyChangedField_omittingUntouchedKeys() = runTest {
        backend.enqueue(Fixtures.okBody(CONFIG_INACTIVE_JSON))
        // Only pre_roll changed -> the body must carry pre_roll_enabled and NOT the two numeric keys.
        val result = repo().updateAdConfig(
            sessionId = "bcs_1",
            preRollEnabled = false,
            durationSeconds = null,
            skipAfterSeconds = null,
        )
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/broadcast/sessions/bcs_1/ad-config", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals(false, body["pre_roll_enabled"])
        assertFalse(body.containsKey("mid_roll_ad_break_duration_seconds"))
        assertFalse(body.containsKey("mid_roll_skip_after_seconds"))
    }

    @Test
    fun updateAdConfig_patches_onlyDuration_omittingOthers() = runTest {
        backend.enqueue(Fixtures.okBody(CONFIG_INACTIVE_JSON))
        val result = repo().updateAdConfig(
            sessionId = "bcs_1",
            preRollEnabled = null,
            durationSeconds = 45,
            skipAfterSeconds = null,
        )
        assertTrue(result is ApiResult.Success)

        val body = backend.takeRequest().bodyJson()
        // Moshi serializes JSON numbers as Double in the loosely-typed map.
        assertEquals(45.0, body["mid_roll_ad_break_duration_seconds"])
        assertFalse(body.containsKey("pre_roll_enabled"))
        assertFalse(body.containsKey("mid_roll_skip_after_seconds"))
    }

    @Test
    fun triggerAdBreak_postsNoBody_mapsAdBreakOut() = runTest {
        backend.enqueue(Fixtures.okBody(AD_BREAK_JSON))
        val result = repo().triggerAdBreak("bcs_1")
        assertTrue(result is ApiResult.Success)
        val adBreak = (result as ApiResult.Success).data
        assertEquals(30, adBreak.durationSeconds)
        assertEquals(1_700_000_000L, adBreak.startedAt)
        assertEquals(5, adBreak.skipAfterSeconds)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/ad-break", req.requestUrl?.encodedPath)
        assertEquals(0L, req.bodySize)
    }

    @Test
    fun endAdBreak_ackBody_succeeds() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().endAdBreak("bcs_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/ad-break/end", req.requestUrl?.encodedPath)
    }

    @Test
    fun endAdBreak_emptyBody_succeeds() = runTest {
        // Empty 200 body -> Response<Unit> success-by-isSuccessful (no Moshi parse on an empty body).
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().endAdBreak("bcs_1")
        assertTrue(result is ApiResult.Success)
    }

    @Test
    fun updateAdConfig_422_mapsDetail() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","mid_roll_ad_break_duration_seconds"],"msg":"out of range",
                    "type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().updateAdConfig(
            sessionId = "bcs_1",
            preRollEnabled = null,
            durationSeconds = 99,
            skipAfterSeconds = null,
        )
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    private companion object {
        const val CONFIG_INACTIVE_JSON = """
            {"session_id":"bcs_1","pre_roll_enabled":true,"mid_roll_ad_break_duration_seconds":30,
             "mid_roll_skip_after_seconds":5,"ad_break_active":false,"ad_break_started_at":null,
             "total_ad_breaks":2}
        """

        const val CONFIG_ACTIVE_JSON = """
            {"session_id":"bcs_1","pre_roll_enabled":true,"mid_roll_ad_break_duration_seconds":30,
             "mid_roll_skip_after_seconds":5,"ad_break_active":true,"ad_break_started_at":1700000000,
             "total_ad_breaks":3}
        """

        const val AD_BREAK_JSON = """
            {"ok":true,"duration_seconds":30,"started_at":1700000000,"skip_after_seconds":5}
        """
    }
}
