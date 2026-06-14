package com.testlogon.android.feature.fanclub

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.fanclub.FanClubChannel
import com.testlogon.android.data.fanclub.FanClubChannelItem
import com.testlogon.android.data.fanclub.FanClubMember
import com.testlogon.android.data.fanclub.FanClubMemberPage
import com.testlogon.android.data.fanclub.FanClubMessage
import com.testlogon.android.data.fanclub.FanClubReaction
import com.testlogon.android.data.fanclub.FanClubRepository
import com.testlogon.android.data.fanclub.FanClubTier
import com.testlogon.android.data.fanclub.FanClubTierSection

/** AND-238/239/240 — in-memory [FanClubRepository] fake for ViewModel + paging unit tests. */
class FakeFanClubRepository(
    var channelsResult: ApiResult<List<FanClubTierSection>> = ApiResult.Success(emptyList()),
    var tiersResult: ApiResult<List<FanClubTier>> = ApiResult.Success(emptyList()),
    /** Member pages keyed by cursor (null = first page). */
    var memberPages: Map<String?, FanClubMemberPage> = emptyMap(),
    var memberResultOverride: ApiResult<FanClubMemberPage>? = null,
    /** Message pages keyed by `before` (null = newest page). */
    var messagePages: Map<String?, ApiResult<List<FanClubMessage>>> = emptyMap(),
    var postResult: ApiResult<FanClubMessage> = success(message("m_posted")),
    var reactionResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var userId: String? = "me",
) : FanClubRepository {

    var channelsCalls = 0
    var postCalls = 0
    var reactionCalls = 0
    var deleteCalls = 0
    var messageCalls = 0

    override suspend fun getChannelsByTier(creatorId: String?): ApiResult<List<FanClubTierSection>> {
        channelsCalls++
        return channelsResult
    }

    override suspend fun getTiers(creatorId: String?): ApiResult<List<FanClubTier>> = tiersResult

    override suspend fun getTierMembers(tierId: String, cursor: String?, limit: Int): ApiResult<FanClubMemberPage> {
        memberResultOverride?.let { return it }
        return ApiResult.Success(memberPages[cursor] ?: FanClubMemberPage(emptyList(), null, null))
    }

    override suspend fun getMessages(channelId: String, before: String?, limit: Int): ApiResult<List<FanClubMessage>> {
        messageCalls++
        return messagePages[before] ?: ApiResult.Success(emptyList())
    }

    override suspend fun postText(channelId: String, text: String): ApiResult<FanClubMessage> {
        postCalls++
        return postResult
    }

    override suspend fun toggleReaction(channelId: String, messageId: String, emoji: String): ApiResult<Unit> {
        reactionCalls++
        return reactionResult
    }

    override suspend fun deleteMessage(channelId: String, messageId: String): ApiResult<Unit> {
        deleteCalls++
        return deleteResult
    }

    override suspend fun currentUserId(): String? = userId

    companion object {
        fun <T> success(value: T): ApiResult<T> = ApiResult.Success(value)
        fun failure(status: Int = 500, message: String = "boom"): ApiResult<Nothing> =
            ApiResult.Failure(ApiError(status = status, message = message))

        fun channel(id: String, name: String = id, level: Int = 0) = FanClubChannel(
            id = id, name = name, description = null, minTierLevel = level,
            messageCount = 0, lastMessageAtEpochSeconds = 0, lastMessagePreview = null,
            pinnedMessageId = null, slowmodeSeconds = 0, maxMessageLength = 0,
        )

        fun tier(id: String, level: Int = 0, name: String = id) = FanClubTier(
            id = id, planId = "plan_$id", name = name, level = level, color = null,
            badgeEmoji = null, badgeImageUrl = null, description = null, memberCount = 0,
            sortOrder = level, active = true,
        )

        fun section(level: Int, accessible: Boolean, channels: List<FanClubChannel>, tier: FanClubTier? = null) =
            FanClubTierSection(
                tier = tier,
                level = level,
                channels = channels.map { FanClubChannelItem(it, isAccessible = accessible) },
            )

        fun message(id: String, sender: String = "usr_9", deleted: Boolean = false) = FanClubMessage(
            id = id, channelId = "c", senderId = sender, senderDisplayName = "Sender",
            senderBadge = null, text = "hi", kind = "text", replyToMessageId = null,
            reactions = listOf(FanClubReaction("🔥", 1, reactedByMe = false)),
            createdAtEpochSeconds = 0, deleted = deleted,
        )

        fun member(id: String) = FanClubMember(
            userId = id, displayName = id, handle = "@$id", avatarUrl = null,
            tierLabel = "Gold", subscribedSinceEpochSeconds = null,
        )
    }
}
