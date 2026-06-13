package com.testlogon.android.feature.broadcast.moderation

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.time.Instant

/**
 * AND-313 — MockWebServer contract tests for [ModerationRepositoryImpl] over [ModerationApi]. Verifies verb +
 * resolved path + body for the host mute / host delete and the delegate ban / unban / delete / pin / unpin /
 * list-bans / moderation-log. Asserts the host mute body { target_user_id, duration_seconds }, the delegate
 * ban body { user_id, reason } at the `ui/broadcast/delegate/{cid}/...` path, the empty-body DELETE, the plain
 * array log decode (epoch -> Instant, unknown moderation_type -> a safe default), the empty-200-body success
 * via Response of Unit, 422 + 403 detail mapping, and the mute / delete ROUTING (host vs. delegate). Each
 * request body is read exactly ONCE.
 */
class ModerationRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ModerationRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return ModerationRepositoryImpl(
            api = retrofit.create(ModerationApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun hostMute_postsTargetUserId_decodesMutedUntil() = runTest {
        backend.enqueue(Fixtures.okBody(MUTE_RESULT_JSON))
        val result = repo().mute("bcs_1", creatorId = null, userId = "usr_9", spec = MuteSpec(300L))
        assertTrue(result is ApiResult.Success)
        assertEquals(Instant.ofEpochSecond(1749322800L), (result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/chat/mute", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("usr_9", body["target_user_id"])
        assertEquals(300.0, body["duration_seconds"])
        // The host mute has NO reason field.
        assertNull(body["reason"])
    }

    @Test
    fun delegateMute_routesToDelegatePath_whenCreatorIdSet() = runTest {
        backend.enqueue(Fixtures.okBody(MUTE_RESULT_JSON))
        val result = repo().mute("bcs_1", creatorId = "cr_5", userId = "usr_9", spec = MuteSpec(3600L))
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/mute", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        // Delegate mute uses user_id (not target_user_id).
        assertEquals("usr_9", body["user_id"])
        assertEquals(3600.0, body["duration_seconds"])
    }

    @Test
    fun hostDelete_sendsDeleteWithNoBody() = runTest {
        backend.enqueue(Fixtures.okBody("{\"ok\":true,\"message_id\":\"cm_1\"}"))
        val result = repo().deleteMessage("bcs_1", creatorId = null, messageId = "cm_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/broadcast/sessions/bcs_1/chat/cm_1", req.requestUrl?.encodedPath)
        assertTrue("host delete sends no body", req.body.readUtf8().isBlank())
    }

    @Test
    fun delegateDelete_routesToDelegatePath_whenCreatorIdSet() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().deleteMessage("bcs_1", creatorId = "cr_5", messageId = "cm_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/chat/cm_1", req.requestUrl?.encodedPath)
    }

    @Test
    fun emptyBody200_succeedsViaResponseUnit() = runTest {
        // An EMPTY 200 body must be success (Response of Unit), not a Moshi EOF.
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().unpin("bcs_1", creatorId = "cr_5", messageId = "cm_1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/chat/cm_1/pin", req.requestUrl?.encodedPath)
    }

    @Test
    fun delegateBan_postsUserIdAndReason_toDelegatePath() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().ban("bcs_1", creatorId = "cr_5", userId = "usr_9", reason = "spam")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/ban", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("usr_9", body["user_id"])
        assertEquals("spam", body["reason"])
    }

    @Test
    fun delegateUnban_sendsDeleteToBanUserPath() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().unban("bcs_1", creatorId = "cr_5", userId = "usr_9")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/ban/usr_9", req.requestUrl?.encodedPath)
    }

    @Test
    fun pin_postsToPinPath_decodesPinned() = runTest {
        backend.enqueue(Fixtures.okBody("{\"ok\":true,\"message_id\":\"cm_1\",\"pinned\":true}"))
        val result = repo().pin("bcs_1", creatorId = "cr_5", messageId = "cm_1")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/chat/cm_1/pin", req.requestUrl?.encodedPath)
    }

    @Test
    fun log_decodesPlainArray_epochToInstant_unknownTypeSafe() = runTest {
        backend.enqueue(Fixtures.okBody(LOG_JSON))
        val result = repo().moderationLog("bcs_1", creatorId = "cr_5")
        assertTrue(result is ApiResult.Success)
        val entries = (result as ApiResult.Success).data
        assertEquals(3, entries.size)
        assertEquals(ModerationActionType.BAN, entries[0].action)
        assertEquals(Instant.ofEpochSecond(1749322800L), entries[0].createdAt)
        assertEquals("spam", entries[0].reason)
        assertEquals(ModerationActionType.DELETE, entries[1].action)
        // Unknown moderation_type maps to a safe default, never throws.
        assertEquals(ModerationActionType.UNKNOWN, entries[2].action)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals(
            "/ui/broadcast/delegate/cr_5/sessions/bcs_1/moderation-log",
            req.requestUrl?.encodedPath,
        )
        assertEquals("100", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun listBans_decodesPlainArray() = runTest {
        backend.enqueue(Fixtures.okBody(BANS_JSON))
        val result = repo().listBans("bcs_1", creatorId = "cr_5")
        assertTrue(result is ApiResult.Success)
        val bans = (result as ApiResult.Success).data
        assertEquals(1, bans.size)
        assertEquals("usr_9", bans[0].userId)
        assertEquals("Ada", bans[0].displayName)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/broadcast/delegate/cr_5/sessions/bcs_1/bans", req.requestUrl?.encodedPath)
    }

    @Test
    fun delegateOnlyAction_blankCreatorId_failsWithoutNetwork() = runTest {
        val result = repo().ban("bcs_1", creatorId = "", userId = "usr_9", reason = null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun hostMute_422_mapsToFailureWithNormalizedDetail() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","duration_seconds"],"msg":"ensure this value is less than or equal to 86400","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().mute("bcs_1", creatorId = null, userId = "usr_9", spec = MuteSpec(999999L))
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(422, error.status)
        assertTrue(error.message.contains("less than or equal to 86400"))
    }

    @Test
    fun ban_403_mapsToAuthFailure() = runTest {
        backend.enqueue(Fixtures.error("\"forbidden\"", 403))
        val result = repo().ban("bcs_1", creatorId = "cr_5", userId = "usr_9", reason = null)
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(403, error.status)
        assertTrue(error.isAuth)
    }

    private companion object {
        const val MUTE_RESULT_JSON =
            """{"target_user_id":"usr_9","muted_until":1749322800,"session_id":"bcs_1"}"""

        const val LOG_JSON = """
            [
              {"event_id":"ev_1","moderator_id":"mod_1","moderator_display_name":"Mod One",
               "moderation_type":"ban","target_user_id":"usr_9","details":{"reason":"spam"},"ts":1749322800},
              {"event_id":"ev_2","moderator_id":"mod_1","moderator_display_name":"Mod One",
               "moderation_type":"delete","target_message_id":"cm_1","details":{},"ts":1749322700},
              {"event_id":"ev_3","moderator_id":"mod_1","moderator_display_name":"Mod One",
               "moderation_type":"frobnicate","details":{},"ts":1749322600}
            ]
        """

        const val BANS_JSON = """
            [{"user_id":"usr_9","display_name":"Ada","reason":"spam","moderator_id":"mod_1","ts":1749322800}]
        """
    }
}
