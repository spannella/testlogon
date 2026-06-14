package com.testlogon.android.data.fanclub

/**
 * AND-238 / AND-239 / AND-240 — framework-free fan-club domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/subscriptions, data/messaging):
 *  - Timestamps are epoch-seconds Longs (NOT java.time) so this stays JVM-unit-testable.
 *  - Mapping is TOTAL: absent optionals -> null, absent maps/lists -> empty; no exceptions thrown.
 *  - DTOs never leak past the repository (the ViewModels/UI consume only these domain types).
 */

// ---- AND-238: channels + tier grouping ----

/** A fan-club channel (the consumer-facing read of [ChannelDto]). */
data class FanClubChannel(
    val id: String,
    val name: String,
    val description: String?,
    /** Integer tier LEVEL required to read; 0 => free/all-access. Matched to [FanClubTier.level]. */
    val minTierLevel: Int,
    val messageCount: Int,
    val lastMessageAtEpochSeconds: Long,
    val lastMessagePreview: String?,
    val pinnedMessageId: String?,
    val slowmodeSeconds: Int,
    val maxMessageLength: Int,
)

/** A fan-club tier (the consumer-facing read of [TierDto]); price is NOT on the tier (see plan_id). */
data class FanClubTier(
    val id: String,
    val planId: String?,
    val name: String,
    val level: Int,
    val color: String?,
    val badgeEmoji: String?,
    val badgeImageUrl: String?,
    val description: String?,
    val memberCount: Int,
    val sortOrder: Int,
    val active: Boolean,
)

/** A channel plus the derived per-user access flag the UI renders. */
data class FanClubChannelItem(
    val channel: FanClubChannel,
    /** Advisory only (server is authoritative): activeTierLevel >= channel.minTierLevel. */
    val isAccessible: Boolean,
)

/**
 * Channels grouped under a tier section. [tier] is the fan-club tier matched by `level`; it is null for
 * the free/level-0 group (or for an orphan channel whose level has no matching tier).
 */
data class FanClubTierSection(
    val tier: FanClubTier?,
    /** The level this section keys on (a channel's minTierLevel / a tier's level). */
    val level: Int,
    val channels: List<FanClubChannelItem>,
) {
    /** Stable section key for LazyColumn sticky headers. */
    val key: String get() = tier?.id ?: "level_$level"
    /** Whether the current user can access this whole tier (true when at least one channel is open). */
    val isUnlocked: Boolean get() = channels.any { it.isAccessible }
}

// ---- AND-240: tier members ----

/** A roster member of a tier (UI model). [displayName] resolves the fallback chain. */
data class FanClubMember(
    val userId: String,
    val displayName: String,
    val handle: String?,
    val avatarUrl: String?,
    val tierLabel: String?,
    val subscribedSinceEpochSeconds: Long?,
)

// ---- AND-239: channel messages ----

/** A channel message (the consumer-facing read of [ChannelMessageDto]). */
data class FanClubMessage(
    val id: String,
    val channelId: String?,
    val senderId: String,
    val senderDisplayName: String,
    val senderBadge: FanClubBadge?,
    val text: String,
    /** Type discriminator (verified: `kind`, NOT `type`). Unknown kinds render as text/unsupported. */
    val kind: String,
    val replyToMessageId: String?,
    /** Derived reaction summaries (count + whether the current user reacted). */
    val reactions: List<FanClubReaction>,
    val createdAtEpochSeconds: Long,
    val deleted: Boolean,
)

/** A sender tier badge. */
data class FanClubBadge(
    val tierName: String?,
    val tierLevel: Int?,
    val badgeEmoji: String?,
)

/** A derived per-emoji reaction summary (from the `Map<emoji, Map<userId, bool>>` wire shape). */
data class FanClubReaction(
    val emoji: String,
    val count: Int,
    /** True when [currentUserId] is among the reactors. */
    val reactedByMe: Boolean,
)

// ---- Mappers (DTO -> domain) ----

internal fun ChannelDto.toDomain(): FanClubChannel = FanClubChannel(
    id = channelId,
    name = name,
    description = description?.takeIf { it.isNotBlank() },
    minTierLevel = minTierLevel,
    messageCount = messageCount,
    lastMessageAtEpochSeconds = lastMessageAt,
    lastMessagePreview = lastMessagePreview?.takeIf { it.isNotBlank() },
    pinnedMessageId = pinnedMessageId,
    slowmodeSeconds = slowmodeSeconds,
    maxMessageLength = maxMessageLength,
)

internal fun TierDto.toDomain(): FanClubTier = FanClubTier(
    id = tierId,
    planId = planId,
    name = name,
    level = level,
    color = color,
    badgeEmoji = badgeEmoji,
    badgeImageUrl = badgeImageUrl,
    description = description?.takeIf { it.isNotBlank() },
    memberCount = memberCount,
    sortOrder = sortOrder,
    active = active,
)

/** Drops rows missing a user id (defensive — keeps the page rendering). Returns null to be filtered. */
internal fun TierMemberDto.toDomainOrNull(): FanClubMember? {
    val id = userId?.takeIf { it.isNotBlank() } ?: return null
    val name = displayName?.takeIf { it.isNotBlank() }
        ?: username?.takeIf { it.isNotBlank() }
        ?: id
    val handle = username?.takeIf { it.isNotBlank() }?.let { "@$it" }
    return FanClubMember(
        userId = id,
        displayName = name,
        handle = handle,
        avatarUrl = avatarUrl?.takeIf { it.isNotBlank() },
        tierLabel = tierName?.takeIf { it.isNotBlank() },
        subscribedSinceEpochSeconds = subscribedSince,
    )
}

internal fun MemberBadgeDto.toDomain(): FanClubBadge = FanClubBadge(
    tierName = tierName?.takeIf { it.isNotBlank() },
    tierLevel = tierLevel,
    badgeEmoji = badgeEmoji?.takeIf { it.isNotBlank() },
)

/**
 * Maps a channel message, deriving per-emoji reaction summaries from the
 * `Map<emoji, Map<userId, bool>>` wire shape. [currentUserId] decides the `reactedByMe` flag.
 */
internal fun ChannelMessageDto.toDomain(currentUserId: String?): FanClubMessage = FanClubMessage(
    id = messageId,
    channelId = channelId,
    senderId = senderId,
    senderDisplayName = senderDisplayName,
    senderBadge = senderBadge?.toDomain(),
    text = text,
    kind = kind.ifBlank { "text" },
    replyToMessageId = replyToMessageId,
    reactions = reactions
        .map { (emoji, reactors) ->
            val active = reactors.filterValues { it }
            FanClubReaction(
                emoji = emoji,
                count = active.size,
                reactedByMe = currentUserId != null && active.containsKey(currentUserId),
            )
        }
        .filter { it.count > 0 }
        .sortedByDescending { it.count },
    createdAtEpochSeconds = createdAt,
    deleted = deleted,
)

// ---- AND-238: pure grouping logic (unit-tested directly) ----

/**
 * Groups [channels] into tier sections joined to [tiers] by `level == minTierLevel`, derives per-channel
 * access from [activeTierLevel] (the user's active fan-club tier level; 0 when not subscribed), and
 * sorts sections ascending by tier level/sort_order (the free/level-0 group first). Within a section,
 * channels are ordered by name (the backend ChannelOut has no `position` field — documented choice).
 *
 * This is pure (no Android, no I/O) so it is JVM-unit-testable in isolation.
 */
internal fun groupChannelsByTier(
    channels: List<FanClubChannel>,
    tiers: List<FanClubTier>,
    activeTierLevel: Int,
): List<FanClubTierSection> {
    val tierByLevel: Map<Int, FanClubTier> = tiers.associateBy { it.level }
    return channels
        .groupBy { it.minTierLevel }
        .map { (level, group) ->
            val tier = tierByLevel[level]
            FanClubTierSection(
                tier = tier,
                level = level,
                channels = group
                    .sortedBy { it.name.lowercase() }
                    .map { FanClubChannelItem(channel = it, isAccessible = activeTierLevel >= level) },
            )
        }
        .sortedWith(
            compareBy<FanClubTierSection> { it.tier?.sortOrder ?: it.level }.thenBy { it.level },
        )
}
