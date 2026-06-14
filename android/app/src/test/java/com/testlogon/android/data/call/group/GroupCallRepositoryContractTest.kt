package com.testlogon.android.data.call.group

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
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-299 — contract tests for [GroupCallRepositoryImpl] against MockWebServer (real Retrofit/Moshi).
 *
 * Verifies the group control-plane wire contract: verbs/paths, request bodies (conversation_id, mode), and
 * DTO -> domain mapping (isHost from creator_user_id; micMuted from !media_status.audio; participant count;
 * ICE servers from signaling.ice_servers). Body JSON is read ONCE per request.
 */
class GroupCallRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): GroupCallRepositoryImpl {
        val api = backend.retrofit(moshi).create(GroupCallApi::class.java)
        return GroupCallRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun create_posts201_mapsDomain_isHostAndMicMuted() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"call_id":"g_1","conversation_id":"conv_1","creator_user_id":"u_self",
                 "state":"active","mode":"video","max_participants":8,"current_participant_count":2,
                 "participants":[
                   {"user_id":"u_self","display_name":"Me","joined_at":100,
                    "media_status":{"audio":false,"video":true,"screen":false},
                    "connection_quality":"good","state":"connected"},
                   {"user_id":"u_2","display_name":"Bo","joined_at":120,
                    "media_status":{"audio":true,"video":false,"screen":false},
                    "connection_quality":"poor","state":"connecting"}
                 ],
                 "signaling":{"mode":"mesh","ice_servers":[
                    {"urls":["turn:turn.example.com:3478"],"username":"u","credential":"c"}]}}
                """.trimIndent(),
                code = 201,
            ),
        )
        val result = repo().create(conversationId = "conv_1", mode = "video", selfUserId = "u_self")
        assertTrue(result is ApiResult.Success)
        val call = (result as ApiResult.Success).data
        assertEquals("g_1", call.callId)
        assertEquals(2, call.participants.size)
        val self = call.participants.first { it.userId == "u_self" }
        assertTrue(self.isHost)
        assertTrue(self.isSelf)
        // media_status.audio=false -> micMuted=true.
        assertTrue(self.micMuted)
        assertFalse(self.cameraOff)
        val peer = call.participants.first { it.userId == "u_2" }
        assertFalse(peer.isHost)
        // ICE servers come from signaling.ice_servers.
        assertEquals(1, call.iceServers.size)
        assertEquals(listOf("turn:turn.example.com:3478"), call.iceServers.first().urls)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calls/group/create", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("conv_1", body["conversation_id"])
        assertEquals("video", body["mode"])
    }

    @Test
    fun join_postsPath_mapsParticipants() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"call_id":"g_9","state":"active","mode":"video","current_participant_count":1,
                 "participants":[
                   {"user_id":"u_self","joined_at":1,
                    "media_status":{"audio":true,"video":true,"screen":false},"state":"connected"}],
                 "signaling":{"mode":"mesh","ice_servers":[]}}
                """.trimIndent(),
            ),
        )
        val result = repo().join(
            callId = "g_9",
            conversationId = "conv_9",
            creatorUserId = "u_host",
            selfUserId = "u_self",
        )
        assertTrue(result is ApiResult.Success)
        val call = (result as ApiResult.Success).data
        assertEquals("conv_9", call.conversationId)
        assertEquals("u_host", call.creatorUserId)
        assertEquals(1, call.participants.size)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calls/group/g_9/join", req.requestUrl?.encodedPath)
    }

    @Test
    fun leave_mapsFlags() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"call_ended":false,"remaining_participants":2}"""),
        )
        val result = repo().leave("g_3")
        assertTrue(result is ApiResult.Success)
        val leave = (result as ApiResult.Success).data
        assertTrue(leave.ok)
        assertFalse(leave.callEnded)
        assertEquals(2, leave.remainingParticipants)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/calls/group/g_3/leave", req.requestUrl?.encodedPath)
    }

    @Test
    fun media_patches_sendsToggles_mapsStatus() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"ok":true,"media_status":{"audio":false,"video":true,"screen":false}}"""),
        )
        val result = repo().media("g_4", audio = false)
        assertTrue(result is ApiResult.Success)
        val media = (result as ApiResult.Success).data
        assertFalse(media.audio)
        assertTrue(media.video)

        val req = backend.takeRequest()
        assertEquals("PATCH", req.method)
        assertEquals("/ui/calls/group/g_4/media", req.requestUrl?.encodedPath)
        assertEquals(false, req.bodyJson()["audio"])
    }

    @Test
    fun participants_getsRoster_mapsHost() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                {"participants":[
                   {"user_id":"u_host","joined_at":1,"media_status":{"audio":true,"video":true,"screen":false}},
                   {"user_id":"u_b","joined_at":2,"media_status":{"audio":true,"video":true,"screen":false}}],
                 "total_active":2,"total_joined":2}
                """.trimIndent(),
            ),
        )
        val result = repo().participants("g_5", creatorUserId = "u_host", selfUserId = "u_b")
        assertTrue(result is ApiResult.Success)
        val roster = (result as ApiResult.Success).data
        assertEquals(2, roster.size)
        assertTrue(roster.first { it.userId == "u_host" }.isHost)
        assertTrue(roster.first { it.userId == "u_b" }.isSelf)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/calls/group/g_5/participants", req.requestUrl?.encodedPath)
    }

    @Test
    fun active_getsProbe_mapsFields() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"active":true,"call_id":"g_6","state":"active","current_participant_count":3}"""),
        )
        val result = repo().active("conv_6")
        assertTrue(result is ApiResult.Success)
        val active = (result as ApiResult.Success).data
        assertTrue(active.active)
        assertEquals("g_6", active.callId)
        assertEquals(3, active.currentParticipantCount)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/calls/group/active/conv_6", req.requestUrl?.encodedPath)
    }

    @Test
    fun create_422_mapsToFailure_neverThrows() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"field required","type":"value_error.missing"}]""", 422))
        val result = repo().create(conversationId = "c", mode = "video")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun leave_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().leave("g_7")
        assertTrue(result is ApiResult.NetworkError)
        assertTrue((result as ApiResult.NetworkError).isTimeout)
    }
}
