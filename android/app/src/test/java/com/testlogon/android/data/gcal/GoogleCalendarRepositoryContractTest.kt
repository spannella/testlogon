package com.testlogon.android.data.gcal

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-273 — MockWebServer contract tests for [GoogleCalendarRepositoryImpl]. Verifies the verified
 * verbs/paths/params for connect/start, status, calendars, mappings, disconnect and sync/run, plus that
 * startConnect persists the OAuth state/nonce and disconnect clears the cached connection.
 */
class GoogleCalendarRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val store = FakeGoogleCalendarStore()

    private fun repo(): GoogleCalendarRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return GoogleCalendarRepositoryImpl(
            api = retrofit.create(GoogleCalendarApi::class.java),
            store = store,
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun startConnect_postsStart_decodesUrl_persistsStateNonce() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"provider":"google","authorization_url":"http://host/mock/google-calendar/x",
                   "state":"abc123","nonce":"n-xyz","expires_at_utc":"2026-06-06T12:05:00Z"}""",
            ),
        )
        val result = repo().startConnect()
        assertTrue(result is ApiResult.Success)
        assertEquals("http://host/mock/google-calendar/x", (result as ApiResult.Success).data.authorizationUrl)
        assertEquals("abc123", store.pendingOauth()?.state)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calendar/integrations/google/connect/start", req.requestUrl?.encodedPath)
    }

    @Test
    fun status_getsStatus_connectionActive() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"provider":"google","connection_active":true,"sync_enabled":true,
                   "writeback_enabled":false,"reauth_required":false,"sync_health":"healthy",
                   "last_sync_status":"ok","last_sync_at_utc":"2026-06-06T11:00:00Z",
                   "rollout_mode":"cohort","rollout_percent":25,"in_rollout_cohort":true}""",
            ),
        )
        val result = repo().refreshStatus()
        assertTrue(result is ApiResult.Success)
        assertEquals(ConnectPhase.CONNECTED, (result as ApiResult.Success).data.phase)
        assertEquals("/ui/calendar/integrations/google/status", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun calendars_decodesCalendarsEnvelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"calendars":[
                   {"google_calendar_id":"gcal_primary","summary":"user@example.com","access_role":"owner",
                    "primary":true,"mapped_internal_calendar_id":"cal_internal_1"},
                   {"google_calendar_id":"gcal_team","summary":"Team","access_role":"reader",
                    "primary":false,"mapped_internal_calendar_id":null}
                   ]}""",
            ),
        )
        val result = repo().listProviderCalendars()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals(2, list.size)
        assertEquals("gcal_primary", list.first().googleCalendarId)
        assertTrue(list.first().primary)
        assertEquals("/ui/calendar/integrations/google/calendars", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun createMapping_postsBody() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"mapping_id":"map_1","provider":"google","user_sub":"u_1",
                   "internal_calendar_id":"cal_internal_1","google_calendar_id":"gcal_team",
                   "active":true,"created_at_utc":"","updated_at_utc":"","unmapped_at_utc":""}""",
            ),
        )
        val result = repo().createMapping("cal_internal_1", "gcal_team")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calendar/integrations/google/mappings", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"internal_calendar_id\":\"cal_internal_1\""))
        assertTrue(body.contains("\"google_calendar_id\":\"gcal_team\""))
    }

    @Test
    fun disconnect_postsAndClearsConnection() = runTest {
        store.saveConnection(active = true, accountEmail = "user@example.com")
        backend.enqueue(
            Fixtures.okBody(
                """{"provider":"google","connection_id":"conn_1","account_email":"user@example.com",
                   "active":false,"revoked":true,"revoke_status":"revoked",
                   "disconnected_at_utc":"2026-06-06T12:10:00Z"}""",
            ),
        )
        val result = repo().disconnect()
        assertTrue(result is ApiResult.Success)
        assertEquals(false, store.cachedConnection()?.connectionActive)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calendar/integrations/google/disconnect", req.requestUrl?.encodedPath)
    }

    @Test
    fun runSync_postsMode() = runTest {
        backend.enqueue(Fixtures.okBody("""{"accepted":true,"mode":"incremental","rate_limited":false,"metrics":{}}"""))
        val result = repo().runSync()
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calendar/integrations/google/sync/run", req.requestUrl?.encodedPath)
        assertEquals("incremental", req.requestUrl?.queryParameter("mode"))
    }

    @Test
    fun completeConnect_stateMismatch_aborts_doesNotCallCallback() = runTest {
        store.savePendingOauth(state = "good", nonce = "n")
        val result = repo().completeConnect(code = "c", state = "bad")
        assertTrue(result is ApiResult.Failure)
        assertEquals(400, (result as ApiResult.Failure).error.status)
        // No request should have been made.
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun status_401_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"unauthorized\"", 401))
        val result = repo().refreshStatus()
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        assertNotNull(backend.takeRequest())
    }
}
