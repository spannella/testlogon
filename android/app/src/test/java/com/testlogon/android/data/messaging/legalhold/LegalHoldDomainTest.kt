package com.testlogon.android.data.messaging.legalhold

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-164 — pure tests for [resolveHold] and the DTO->domain mapper. Covers the active-match truth
 * table: conversation-level vs message-level scoping, `released` ignored, empty list => null.
 */
class LegalHoldDomainTest {

    private fun hold(
        holdId: String = "lh_1",
        conversationId: String = "conv_1",
        messageId: String? = null,
        status: String = "active",
        caseId: String = "CASE-4471",
        reason: String = "Litigation hold for matter 4471",
        createdAt: Long? = 1740926700,
    ) = LegalHoldDto(
        holdId = holdId,
        tenantId = "t1",
        conversationId = conversationId,
        messageId = messageId,
        caseId = caseId,
        reason = reason,
        status = status,
        createdAt = createdAt,
        createdByUserId = "usr_admin",
    )

    @Test
    fun activeConversationHold_resolvesAsConversationSource() {
        val resolved = resolveHold(listOf(hold(messageId = null)), "conv_1", messageId = null)
        requireNotNull(resolved)
        assertEquals(HoldStatus.ACTIVE, resolved.status)
        assertEquals(HoldSource.CONVERSATION, resolved.source)
        assertEquals("CASE-4471", resolved.caseId)
        assertEquals(1740926700L, resolved.createdAtEpochSeconds)
    }

    @Test
    fun releasedHold_isNotResolved_butActiveSibling_is() {
        val holds = listOf(
            hold(holdId = "old", status = "released"),
            hold(holdId = "new", status = "active"),
        )
        assertEquals("new", resolveHold(holds, "conv_1", null)?.holdId)

        // Only-released => null.
        assertNull(resolveHold(listOf(hold(status = "released")), "conv_1", null))
    }

    @Test
    fun messageScopedHold_marksMessage_notConversation() {
        val holds = listOf(hold(messageId = "msg_9"))
        val msgHold = resolveHold(holds, "conv_1", "msg_9")
        requireNotNull(msgHold)
        assertEquals(HoldSource.MESSAGE, msgHold.source)
        // A message-scoped hold does NOT mark the whole conversation held.
        assertNull(resolveHold(holds, "conv_1", null))
    }

    @Test
    fun conversationScopedHold_doesNotMarkArbitraryMessage() {
        val holds = listOf(hold(messageId = null))
        assertNull(resolveHold(holds, "conv_1", "msg_9"))
    }

    @Test
    fun emptyList_returnsNull() {
        assertNull(resolveHold(emptyList(), "conv_1", null))
    }

    @Test
    fun mismatchedConversation_returnsNull() {
        assertNull(resolveHold(listOf(hold(conversationId = "other")), "conv_1", null))
    }

    @Test
    fun statusFromWire_unknownIsNotHeld() {
        assertEquals(HoldStatus.UNKNOWN, HoldStatus.fromWire("expired"))
        assertNull(resolveHold(listOf(hold(status = "expired")), "conv_1", null))
    }

    @Test
    fun holdableExtension_isOnHold() {
        val holdable = object : Holdable {
            override val legalHold: LegalHold? = hold().toDomain()
        }
        val unheld = object : Holdable { override val legalHold: LegalHold? = null }
        assertEquals(true, holdable.isOnHold)
        assertEquals(false, unheld.isOnHold)
    }
}
