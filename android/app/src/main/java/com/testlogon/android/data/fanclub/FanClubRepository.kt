package com.testlogon.android.data.fanclub

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.getOrNull
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.data.subscriptions.SubscriptionState
import com.testlogon.android.data.subscriptions.SubscriptionsRepository
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-238 / AND-239 / AND-240 — fan-club data layer over [FanClubApi].
 *
 * Wraps every call in [ApiResult] (matching the subscriptions/billing repositories): CancellationException
 * is re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError.
 * DTOs are mapped to domain before returning (no raw DTOs leak out).
 *
 * Reuses [SubscriptionsRepository] (AND-234) for the viewer's active subscription so per-channel access
 * (AND-238) and tier ownership can be derived WITHOUT a duplicate subscriptions stack: the active sub's
 * `planId` is matched to a fan-club [FanClubTier.planId] to resolve the viewer's active tier `level`.
 * Reuses [AuthStateStore] for the current user id (used to derive reaction `reactedByMe` + delete-own
 * gating in AND-239).
 */
interface FanClubRepository {

    /** AND-238 — channels joined with tiers + the viewer's access, grouped & ordered by tier. */
    suspend fun getChannelsByTier(creatorId: String?): ApiResult<List<FanClubTierSection>>

    /** AND-240 — the fan-club's tiers (active only, ordered by sort_order/level). */
    suspend fun getTiers(creatorId: String?): ApiResult<List<FanClubTier>>

    /** AND-240 — one page of a tier's members (cursor pagination; normalizes bare-list responses). */
    suspend fun getTierMembers(
        tierId: String,
        cursor: String?,
        limit: Int,
    ): ApiResult<FanClubMemberPage>

    /** AND-239 — one page of a channel's messages (newest-first; [before] = oldest id of newer page). */
    suspend fun getMessages(
        channelId: String,
        before: String?,
        limit: Int,
    ): ApiResult<List<FanClubMessage>>

    /** AND-239 — post a text message (non-idempotent; never auto-retried). */
    suspend fun postText(channelId: String, text: String): ApiResult<FanClubMessage>

    /** AND-239 — toggle a reaction (ASSUMED single-emoji toggle). */
    suspend fun toggleReaction(channelId: String, messageId: String, emoji: String): ApiResult<Unit>

    /** AND-239 — delete a message (success 200/204). */
    suspend fun deleteMessage(channelId: String, messageId: String): ApiResult<Unit>

    /** AND-239 — the current signed-in user id (for ownership / reactedByMe), or null. */
    suspend fun currentUserId(): String?
}

/** AND-240 — one page of tier members with the cursor for the next page + an optional total count. */
data class FanClubMemberPage(
    val members: List<FanClubMember>,
    val nextCursor: String?,
    val total: Int?,
)

@Singleton
class FanClubRepositoryImpl @Inject constructor(
    private val api: FanClubApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
    private val subscriptionsRepository: SubscriptionsRepository,
) : FanClubRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getChannelsByTier(creatorId: String?): ApiResult<List<FanClubTierSection>> =
        withContext(io) {
            when (val channels = call { api.getChannels(creatorId) }) {
                is ApiResult.Success -> {
                    // Tiers + active level are advisory joins: a failure here degrades to "level 0" /
                    // null tier headers rather than failing the whole screen.
                    val tiers = call { api.getTiers() }.getOrNull()
                        .orEmpty()
                        .filter { it.active }
                        .map { it.toDomain() }
                    val activeLevel = activeTierLevel(tiers)
                    ApiResult.Success(
                        groupChannelsByTier(
                            channels = channels.data.map { it.toDomain() },
                            tiers = tiers,
                            activeTierLevel = activeLevel,
                        ),
                    )
                }
                is ApiResult.Failure -> channels
                is ApiResult.NetworkError -> channels
            }
        }

    override suspend fun getTiers(creatorId: String?): ApiResult<List<FanClubTier>> = withContext(io) {
        call { api.getTiers() }.map { dtos ->
            dtos.filter { it.active }
                .map { it.toDomain() }
                .sortedWith(compareBy<FanClubTier> { it.sortOrder }.thenBy { it.level })
        }
    }

    override suspend fun getTierMembers(
        tierId: String,
        cursor: String?,
        limit: Int,
    ): ApiResult<FanClubMemberPage> = withContext(io) {
        call { api.getTierMembers(tierId, cursor, limit) }.map { page ->
            FanClubMemberPage(
                members = page.items.mapNotNull { it.toDomainOrNull() },
                nextCursor = page.nextCursor?.takeIf { it.isNotBlank() },
                total = page.total,
            )
        }
    }

    override suspend fun getMessages(
        channelId: String,
        before: String?,
        limit: Int,
    ): ApiResult<List<FanClubMessage>> = withContext(io) {
        val me = currentUserId()
        call { api.getMessages(channelId, before, limit) }.map { dtos ->
            dtos.map { it.toDomain(me) }
        }
    }

    override suspend fun postText(channelId: String, text: String): ApiResult<FanClubMessage> =
        withContext(io) {
            val me = currentUserId()
            call { api.postMessage(channelId, ChannelMessageInDto(text = text)) }.map { it.toDomain(me) }
        }

    override suspend fun toggleReaction(
        channelId: String,
        messageId: String,
        emoji: String,
    ): ApiResult<Unit> = withContext(io) {
        call { api.react(channelId, messageId, ReactionRequestDto(emoji = emoji)).unitOrThrow() }
    }

    override suspend fun deleteMessage(channelId: String, messageId: String): ApiResult<Unit> =
        withContext(io) {
            call { api.deleteMessage(channelId, messageId).unitOrThrow() }
        }

    override suspend fun currentUserId(): String? =
        authStateStore.userSub.first()?.takeIf { it.isNotBlank() }

    /**
     * Resolves the viewer's active fan-club tier level by matching the active subscription's `planId`
     * to a fan-club tier's `planId`. Returns 0 (free) when not subscribed or on any read failure.
     */
    private suspend fun activeTierLevel(tiers: List<FanClubTier>): Int {
        if (tiers.isEmpty()) return 0
        val subs = subscriptionsRepository.getMySubscriptions().getOrNull().orEmpty()
        val activePlanIds = subs
            .filter { it.status == SubscriptionState.ACTIVE || it.status == SubscriptionState.TRIALING }
            .map { it.planId }
            .toSet()
        return tiers
            .filter { it.planId != null && it.planId in activePlanIds }
            .maxOfOrNull { it.level }
            ?: 0
    }

    /** Treats 200/204 (+ empty body) as success; any other code throws an [HttpException]. */
    private fun Response<Unit>.unitOrThrow() {
        if (!isSuccessful) throw HttpException(this)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
