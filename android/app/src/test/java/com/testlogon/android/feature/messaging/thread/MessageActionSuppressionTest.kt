package com.testlogon.android.feature.messaging.thread

import com.testlogon.android.data.messaging.SendStatus
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-164 — pure tests for [allowedActions]: a message on legal hold suppresses ALL destructive/mutating
 * actions; an un-held message exposes the full set. Drives the central UI gate (the server is never
 * relied upon to reject).
 */
class MessageActionSuppressionTest {

    private fun msg(onHold: Boolean) = ThreadMessageUi(
        key = "m1",
        text = "hi",
        isOwn = true,
        createdAtEpochSeconds = 1,
        sendStatus = SendStatus.SENT,
        onHold = onHold,
    )

    @Test
    fun heldMessage_allowsNoActions() {
        assertTrue(msg(onHold = true).allowedActions().isEmpty())
    }

    @Test
    fun unheldMessage_allowsFullSet() {
        assertEquals(MessageAction.entries.toSet(), msg(onHold = false).allowedActions())
    }

    @Test
    fun fullSet_containsEveryDestructiveAction() {
        val all = msg(onHold = false).allowedActions()
        listOf(
            MessageAction.PIN, MessageAction.EDIT, MessageAction.DELETE,
            MessageAction.REVOKE, MessageAction.HIDE,
        ).forEach { assertTrue("missing $it", it in all) }
    }
}
