package com.testlogon.android.data.messaging.presence

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/** AND-145 — MockWebServer contract tests for [PresenceApi]: verb/path/body/query + decode. */
class PresenceApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private fun api(): PresenceApi = backend.retrofit(moshi).create(PresenceApi::class.java)

    @Test
    fun heartbeat_postsDeviceBody_decodesResponse() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ok":true,"user_id":"usr_self","online":true,"last_seen_at":1749126660}""",
            ),
        )
        val resp = api().heartbeat(HeartbeatReq(device = "android"))
        assertTrue(resp.ok)
        assertEquals("usr_self", resp.userId)
        assertEquals(1749126660L, resp.lastSeenAt)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/presence/heartbeat", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("android", body["device"])
    }

    @Test
    fun getPresence_sendsCommaJoinedQuery_decodesBareArray() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [
                  {"user_id":"usr_1","online":true,"last_seen_at":1749126655},
                  {"user_id":"usr_2","online":false,"last_seen_at":1749066131}
                ]
                """.trimIndent(),
            ),
        )
        val list = api().getPresence("usr_1,usr_2")
        assertEquals(2, list.size)
        assertEquals(true, list[0].online)
        assertEquals(false, list[1].online)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/presence", req.requestUrl?.encodedPath)
        assertEquals("usr_1,usr_2", req.requestUrl?.queryParameter("user_ids"))
    }
}
