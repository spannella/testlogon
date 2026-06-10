package com.testlogon.android.data.fanclub

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-238/239/240 — pure mapping + grouping/access logic (no Android, no I/O). */
class FanClubDomainTest {

    private fun channel(id: String, name: String, level: Int) = FanClubChannel(
        id = id,
        name = name,
        description = null,
        minTierLevel = level,
        messageCount = 0,
        lastMessageAtEpochSeconds = 0,
        lastMessagePreview = null,
        pinnedMessageId = null,
        slowmodeSeconds = 0,
        maxMessageLength = 0,
    )

    private fun tier(id: String, level: Int, sort: Int, name: String) = FanClubTier(
        id = id,
        planId = "plan_$id",
        name = name,
        level = level,
        color = null,
        badgeEmoji = null,
        badgeImageUrl = null,
        description = null,
        memberCount = 0,
        sortOrder = sort,
        active = true,
    )

    @Test
    fun grouping_ordersSectionsByTier_freeFirst() {
        val channels = listOf(
            channel("c_gold", "gold-lounge", 3),
            channel("c_free", "general", 0),
            channel("c_bronze", "bronze-chat", 1),
        )
        val tiers = listOf(
            tier("t_bronze", level = 1, sort = 1, name = "Bronze"),
            tier("t_gold", level = 3, sort = 2, name = "Gold"),
            // level 0 has no explicit tier -> "free" group (null tier).
        )
        val sections = groupChannelsByTier(channels, tiers, activeTierLevel = 0)

        assertEquals(listOf(0, 1, 3), sections.map { it.level })
        assertNull(sections[0].tier) // free group
        assertEquals("Bronze", sections[1].tier?.name)
        assertEquals("Gold", sections[2].tier?.name)
    }

    @Test
    fun grouping_ordersChannelsWithinSection_byName() {
        val channels = listOf(
            channel("c2", "zeta", 0),
            channel("c1", "alpha", 0),
        )
        val sections = groupChannelsByTier(channels, tiers = emptyList(), activeTierLevel = 0)
        assertEquals(listOf("alpha", "zeta"), sections.single().channels.map { it.channel.name })
    }

    @Test
    fun access_level0_alwaysAccessible_evenWithNoSubscription() {
        val sections = groupChannelsByTier(listOf(channel("c", "general", 0)), emptyList(), activeTierLevel = 0)
        assertTrue(sections.single().channels.single().isAccessible)
    }

    @Test
    fun access_higherTierLocked_whenActiveBelow() {
        val channels = listOf(channel("c0", "general", 0), channel("c1", "bronze", 1), channel("c3", "gold", 3))
        val tiers = listOf(tier("t1", 1, 1, "Bronze"), tier("t3", 3, 2, "Gold"))
        val sections = groupChannelsByTier(channels, tiers, activeTierLevel = 1)

        val byLevel = sections.associateBy { it.level }
        assertTrue(byLevel.getValue(0).channels.single().isAccessible)
        assertTrue(byLevel.getValue(1).channels.single().isAccessible) // active >= 1
        assertFalse(byLevel.getValue(3).channels.single().isAccessible) // 1 < 3 -> locked
    }

    @Test
    fun channelDto_mapsEpochAndBlankToNull() {
        val dto = ChannelDto(
            channelId = "chan_1",
            name = "general",
            description = "  ",
            minTierLevel = 2,
            lastMessageAt = 1_749_114_720L,
            lastMessagePreview = "",
        )
        val domain = dto.toDomain()
        assertEquals("chan_1", domain.id)
        assertEquals(2, domain.minTierLevel)
        assertEquals(1_749_114_720L, domain.lastMessageAtEpochSeconds)
        assertNull(domain.description)
        assertNull(domain.lastMessagePreview)
    }

    @Test
    fun message_derivesReactionCountAndReactedByMe() {
        val dto = ChannelMessageDto(
            messageId = "msg_1",
            senderId = "usr_9",
            senderDisplayName = "Ada",
            text = "hello",
            kind = "text",
            reactions = mapOf(
                "🔥" to mapOf("usr_1" to true, "usr_2" to true, "me" to true),
                "👍" to mapOf("usr_3" to false), // all-false -> dropped (count 0)
            ),
            createdAt = 1_749_124_800L,
        )
        val domain = dto.toDomain(currentUserId = "me")
        assertEquals(1, domain.reactions.size)
        val fire = domain.reactions.single()
        assertEquals("🔥", fire.emoji)
        assertEquals(3, fire.count)
        assertTrue(fire.reactedByMe)
    }

    @Test
    fun message_unknownKindKept_andReactedFalseWhenNoUser() {
        val dto = ChannelMessageDto(
            messageId = "m",
            kind = "hologram",
            reactions = mapOf("🔥" to mapOf("usr_1" to true)),
        )
        val domain = dto.toDomain(currentUserId = null)
        assertEquals("hologram", domain.kind)
        assertFalse(domain.reactions.single().reactedByMe)
    }

    @Test
    fun member_displayNameFallbackChain_andDropsMissingUserId() {
        assertEquals("Kestrel", TierMemberDto(userId = "u1", username = "kestrel", displayName = "Kestrel").toDomainOrNull()?.displayName)
        assertEquals("@kestrel", TierMemberDto(userId = "u1", username = "kestrel").toDomainOrNull()?.handle)
        assertEquals("kestrel", TierMemberDto(userId = "u2", username = "kestrel").toDomainOrNull()?.displayName)
        assertEquals("u3", TierMemberDto(userId = "u3").toDomainOrNull()?.displayName)
        assertNull(TierMemberDto(userId = null, username = "x").toDomainOrNull()) // no user id -> dropped
    }
}
