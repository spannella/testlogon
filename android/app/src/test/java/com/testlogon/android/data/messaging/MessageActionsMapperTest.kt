package com.testlogon.android.data.messaging

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-140 / AND-142 — pure JVM tests for the action mappers + optimistic-toggle + reactions JSON
 * round-trip. No Android types, no network.
 */
class MessageActionsMapperTest {

    private fun dto(
        reactionsCounts: Map<String, Int>? = null,
        myReactions: List<String>? = null,
        editedAt: Long? = null,
        revokedAt: Long? = null,
    ) = MessageDto(
        messageId = "m1",
        conversationId = "c1",
        senderId = "u1",
        createdAt = 100,
        kind = "text",
        text = "hi",
        reactionsCounts = reactionsCounts,
        myReactions = myReactions,
        editedAt = editedAt,
        revokedAt = revokedAt,
    )

    @Test
    fun toReactions_zipsCountsWithMyReactions_andSortsByCount() {
        val reactions = dto(
            reactionsCounts = mapOf("👍" to 3, "❤️" to 5),
            myReactions = listOf("👍"),
        ).toReactions()
        // Sorted by descending count: ❤️(5) then 👍(3).
        assertEquals(listOf("❤️", "👍"), reactions.map { it.emoji })
        assertEquals(5, reactions[0].count)
        assertFalse(reactions[0].reactedByMe)
        assertTrue(reactions[1].reactedByMe)
    }

    @Test
    fun toReactions_dropsZeroCounts_andEmptyForNull() {
        assertTrue(dto(reactionsCounts = null).toReactions().isEmpty())
        assertTrue(dto(reactionsCounts = mapOf("👍" to 0)).toReactions().isEmpty())
    }

    @Test
    fun deriveLifecycle_revokedWinsOverEdited() {
        assertEquals(MessageLifecycle.REVOKED, dto(revokedAt = 9, editedAt = 5).deriveLifecycle())
        assertEquals(MessageLifecycle.EDITED, dto(editedAt = 5).deriveLifecycle())
        assertEquals(MessageLifecycle.ACTIVE, dto().deriveLifecycle())
    }

    @Test
    fun toDomain_carriesReactionsAndLifecycleAndEditedAt() {
        val msg = dto(
            reactionsCounts = mapOf("👍" to 1),
            myReactions = listOf("👍"),
            editedAt = 222,
        ).toDomain()
        assertEquals(1, msg.reactions.size)
        assertEquals(MessageLifecycle.EDITED, msg.lifecycle)
        assertEquals(222L, msg.editedAtEpochSeconds)
    }

    @Test
    fun reactionDetails_flattensEmojiKeyedReactors() {
        val out = ReactionDetailsOut(
            reactions = mapOf(
                "👍" to listOf(ReactionUserOut("u_2", "Ann", null)),
                "❤️" to listOf(ReactionUserOut("u_3", "Bo", "http://p")),
            ),
        )
        val reactors = out.toReactors().sortedBy { it.userSub }
        assertEquals("u_2", reactors[0].userSub)
        assertEquals("👍", reactors[0].emoji)
        assertEquals("u_3", reactors[1].userSub)
        assertEquals("❤️", reactors[1].emoji)
    }

    @Test
    fun editHistory_mapsNewestFirst() {
        val edits = listOf(
            EditHistoryEntryDto(revision = 1, text = "v1", editedAt = 100),
            EditHistoryEntryDto(revision = 2, text = "v2", editedAt = 200),
        ).toMessageEdits()
        assertEquals(listOf("v2", "v1"), edits.map { it.body })
    }

    @Test
    fun withReactionToggled_addsNewChip() {
        val msg = baseMessage()
        val next = msg.withReactionToggled("👍", add = true)
        assertEquals(1, next.reactions.size)
        assertEquals(1, next.reactions[0].count)
        assertTrue(next.reactions[0].reactedByMe)
    }

    @Test
    fun withReactionToggled_removeDropsChipWhenCountHitsZero() {
        val msg = baseMessage().copy(reactions = listOf(Reaction("👍", 1, reactedByMe = true)))
        val next = msg.withReactionToggled("👍", add = false)
        assertTrue(next.reactions.isEmpty())
    }

    @Test
    fun withReactionToggled_removeDecrementsAndUnsetsMine() {
        val msg = baseMessage().copy(reactions = listOf(Reaction("👍", 3, reactedByMe = true)))
        val next = msg.withReactionToggled("👍", add = false)
        assertEquals(2, next.reactions[0].count)
        assertFalse(next.reactions[0].reactedByMe)
    }

    @Test
    fun withReactionToggled_addWhenAlreadyMine_isNoOp() {
        val msg = baseMessage().copy(reactions = listOf(Reaction("👍", 1, reactedByMe = true)))
        assertEquals(msg.reactions, msg.withReactionToggled("👍", add = true).reactions)
    }

    @Test
    fun reactionsJson_roundTrips() {
        val reactions = listOf(Reaction("👍", 3, true), Reaction("❤️", 1, false))
        val json = reactionsToJson(reactions)
        val back = reactionsFromJson(json)
        assertEquals(reactions, back)
    }

    @Test
    fun reactionsJson_nullAndBlankAreEmpty() {
        assertEquals(null, reactionsToJson(emptyList()))
        assertTrue(reactionsFromJson(null).isEmpty())
        assertTrue(reactionsFromJson("[]").isEmpty())
        assertTrue(reactionsFromJson("garbage").isEmpty())
    }

    private fun baseMessage() = Message(
        id = "m1",
        clientId = "m1",
        conversationId = "c1",
        senderId = "u1",
        text = "hi",
        createdAtEpochSeconds = 100,
    )
}
