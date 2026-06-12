package com.testlogon.android.feature.call.incoming

import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.data.call.CallMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-297 — pure parse tests for [CallPushParser]: valid invite -> notification model, wrong type /
 * missing fields / oversized strings dropped (never throws), terminal events, mode + advisory expires_at.
 */
class CallPushParserTest {

    private val parser = CallPushParser()

    @Test
    fun validInvite_mapsAllFields() {
        val event = parser.parse(
            mapOf(
                "type" to "call.invite",
                "call_id" to "c_1",
                "conversation_id" to "conv_1",
                "caller_user_id" to "u_7",
                "caller_name" to "Jordan Vega",
                "caller_avatar_url" to "https://x/u_7.png",
                "initial_mode" to "video",
                "expires_at" to "1733400030",
            ),
        )
        assertTrue(event is CallEvent.Invite)
        val invite = event as CallEvent.Invite
        assertEquals("c_1", invite.callId)
        assertEquals("conv_1", invite.conversationId)
        assertEquals("u_7", invite.callerUserId)
        assertEquals("Jordan Vega", invite.callerName)
        assertEquals(CallMode.VIDEO, invite.mode)
        assertEquals(1733400030L, invite.expiresAtEpochSeconds)
    }

    @Test
    fun wrongType_dropped() {
        assertNull(parser.parse(mapOf("type" to "message:new", "call_id" to "c")))
    }

    @Test
    fun missingType_dropped() {
        assertNull(parser.parse(mapOf("call_id" to "c")))
    }

    @Test
    fun invite_missingCallId_dropped() {
        assertNull(parser.parse(mapOf("type" to "call.invite", "conversation_id" to "conv")))
    }

    @Test
    fun invite_missingConversation_dropped() {
        assertNull(
            parser.parse(
                mapOf("type" to "call.invite", "call_id" to "c", "caller_user_id" to "u"),
            ),
        )
    }

    @Test
    fun invite_oversizedCallId_dropped() {
        assertNull(
            parser.parse(
                mapOf(
                    "type" to "call.invite",
                    "call_id" to "x".repeat(200),
                    "conversation_id" to "conv",
                    "caller_user_id" to "u",
                ),
            ),
        )
    }

    @Test
    fun invite_defaultMode_audio_andNoExpiry() {
        val invite = parser.parse(
            mapOf(
                "type" to "call.invite",
                "call_id" to "c",
                "conversation_id" to "conv",
                "caller_user_id" to "u",
            ),
        ) as CallEvent.Invite
        assertEquals(CallMode.AUDIO, invite.mode)
        assertNull(invite.expiresAtEpochSeconds)
    }

    @Test
    fun terminalEvents_parse() {
        assertEquals(CallEvent.Ended("c"), parser.parse(mapOf("type" to "call.end", "call_id" to "c")))
        assertEquals(CallEvent.Missed("c"), parser.parse(mapOf("type" to "call.missed", "call_id" to "c")))
        assertEquals(CallEvent.Declined("c"), parser.parse(mapOf("type" to "call.decline", "call_id" to "c")))
        assertEquals(CallEvent.Accepted("c"), parser.parse(mapOf("type" to "call.accept", "call_id" to "c")))
    }
}
