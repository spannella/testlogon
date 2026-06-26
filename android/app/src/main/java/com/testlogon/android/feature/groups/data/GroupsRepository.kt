package com.testlogon.android.feature.groups.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupComment
import com.testlogon.android.core.model.groups.GroupFeedPost
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.model.groups.Contributor
import com.testlogon.android.core.model.groups.GroupCampaign
import com.testlogon.android.core.model.groups.GroupCampaignStats
import com.testlogon.android.core.model.groups.GroupFundraiser
import com.testlogon.android.core.model.groups.TreasuryBalance
import com.testlogon.android.core.model.groups.TreasuryLedgerEntry
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.groups.GroupCreateIn
import com.testlogon.android.core.network.groups.GroupCommentCreateIn
import com.testlogon.android.core.network.groups.GroupPostCreateIn
import com.testlogon.android.core.network.groups.GroupInviteIn
import com.testlogon.android.core.network.groups.GroupUpdateRoleIn
import com.testlogon.android.core.network.groups.GroupCreateCampaignIn
import com.testlogon.android.core.network.groups.GroupCreateFundraiserIn
import com.testlogon.android.core.network.groups.GroupUpdateIn
import com.testlogon.android.core.network.groups.GroupsApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-355 - data layer for the SOCIAL GROUPS surface (distinct from messaging group chats).
 *
 * REUSE: every call REUSES AND-355's [GroupsApi] (which returns RAW DTOs / Response<Unit>); this
 * repository unwraps the ENVELOPE responses ({groups}, {members,count}), maps the DTO to the core-model
 * domain BEFORE the typed [ApiResult], and wraps each call in [call] (mirrors AND-353 OrgsRepository). The
 * empty-body 200 mutations (invite / changeRole / removeMember / leave) are treated as
 * success-by-isSuccessful -> ApiResult.Success(Unit).
 *
 * There is NO Room / disk persistence (no migration) and NO poll loop here.
 */
interface GroupsRepository {

    /** GET the caller's groups (ENVELOPE {groups} -> mapped). Idempotent GET. */
    suspend fun listMyGroups(): ApiResult<List<Group>>

    /**
     * POST a new social group. On success returns the created [Group] (the creator is admin). A 422/4xx
     * surfaces as a Failure carrying the status; transport failures -> NetworkError.
     */
    suspend fun createGroup(
        name: String,
        description: String?,
        visibility: String?,
        topic: String?,
    ): ApiResult<Group>

    /** GET one group's detail (mapped). Idempotent GET. */
    suspend fun getGroup(groupId: String): ApiResult<Group>

    /** GET one group's member roster (ENVELOPE {members,count} -> mapped). Idempotent GET. */
    suspend fun listMembers(groupId: String): ApiResult<List<GroupMember>>

    // ---- Batch-8 (#11): group feed ----

    /** A cold [PagingData] stream of the group's reverse-chronological feed; re-collect to refresh. */
    fun groupFeedPager(groupId: String): Flow<PagingData<GroupFeedPost>>

    /**
     * POST a new post to the group feed (full newsfeed parity: text + multiple images + a single video +
     * an optional paid-lock price). On success returns the created [GroupFeedPost].
     */
    suspend fun createGroupPost(
        groupId: String,
        text: String,
        imageUrls: List<String> = emptyList(),
        videoId: String? = null,
        unlockPriceCents: Int? = null,
    ): ApiResult<GroupFeedPost>

    /** GET one oldest-first page of a group post's comments (ENVELOPE {comments, next_cursor} -> mapped). */
    suspend fun listComments(
        groupId: String,
        postId: String,
        cursor: String? = null,
        limit: Int = 50,
    ): ApiResult<GroupCommentsPage>

    /** POST a comment (text and/or image, optional threaded reply) to a group post. */
    suspend fun addComment(
        groupId: String,
        postId: String,
        text: String?,
        imageUrl: String? = null,
        parentCommentId: String? = null,
    ): ApiResult<GroupComment>

    /** DELETE a group post comment (author or admin/mod). 200 -> Success(Unit). */
    suspend fun deleteComment(groupId: String, postId: String, commentId: String): ApiResult<Unit>

    /** POST an invite (the invitee becomes status="invited" - a PENDING entry). 200/empty -> Success(Unit). */
    suspend fun invite(groupId: String, userId: String): ApiResult<Unit>

    /** PATCH a member's role (moderator|member only; admin is NOT assignable). 200/empty -> Success(Unit). */
    suspend fun changeRole(groupId: String, userId: String, role: GroupRole): ApiResult<Unit>

    /** DELETE a member. 200 -> Success(Unit). */
    suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit>

    /** POST leave (no body). 200 -> Success(Unit). */
    suspend fun leave(groupId: String): ApiResult<Unit>

    // ---- Sub-pages (AND-355): treasury / fundraising / campaigns / settings ----

    /** GET the treasury balance (membership-gated read). */
    suspend fun getTreasuryBalance(groupId: String): ApiResult<TreasuryBalance>

    /** GET the treasury ledger entries (membership-gated read). */
    suspend fun getTreasuryLedger(groupId: String): ApiResult<List<TreasuryLedgerEntry>>

    /** GET the treasury contributors (membership-gated read). */
    suspend fun getTreasuryContributors(groupId: String): ApiResult<List<Contributor>>

    /** GET the group fundraisers (membership-gated read). */
    suspend fun listFundraisers(groupId: String): ApiResult<List<GroupFundraiser>>

    /** POST a new fundraiser (admin-gated -> 403 for non-admins). */
    suspend fun createFundraiser(
        groupId: String,
        title: String,
        description: String?,
        goalCents: Long?,
    ): ApiResult<GroupFundraiser>

    /** GET the group advertising campaigns (membership-gated read). */
    suspend fun listCampaigns(groupId: String): ApiResult<List<GroupCampaign>>

    /** GET per-campaign stats (membership-gated read). */
    suspend fun getCampaignStats(groupId: String, campaignId: String): ApiResult<GroupCampaignStats>

    /** POST a new campaign (admin-gated -> 403 for non-admins). */
    suspend fun createCampaign(
        groupId: String,
        name: String,
        dailyBudgetCents: Long,
        lifetimeBudgetCents: Long,
        creativeText: String?,
    ): ApiResult<GroupCampaign>

    /** PATCH the group settings (admin-gated -> 403 for non-admins). */
    suspend fun updateGroup(
        groupId: String,
        name: String?,
        description: String?,
        visibility: String?,
        topic: String?,
    ): ApiResult<Group>
}

@Singleton
class GroupsRepositoryImpl @Inject constructor(
    private val groupsApi: GroupsApi,
    private val errorParser: ApiErrorParser,
) : GroupsRepository {

    override suspend fun listMyGroups(): ApiResult<List<Group>> = withContext(Dispatchers.IO) {
        call { groupsApi.listMyGroups().groups.map { it.toDomain() } }
    }

    override suspend fun createGroup(
        name: String,
        description: String?,
        visibility: String?,
        topic: String?,
    ): ApiResult<Group> = withContext(Dispatchers.IO) {
        call {
            groupsApi.createGroup(
                GroupCreateIn(
                    name = name,
                    description = description?.takeIf { it.isNotBlank() },
                    visibility = visibility,
                    topic = topic?.takeIf { it.isNotBlank() },
                ),
            ).toDomain()
        }
    }

    override suspend fun getGroup(groupId: String): ApiResult<Group> = withContext(Dispatchers.IO) {
        call { groupsApi.getGroup(groupId).toDomain() }
    }

    override suspend fun listMembers(groupId: String): ApiResult<List<GroupMember>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.listMembers(groupId).members.map { it.toDomain() } }
        }

    override fun groupFeedPager(groupId: String): Flow<PagingData<GroupFeedPost>> =
        Pager(
            config = PagingConfig(pageSize = 20, initialLoadSize = 20, prefetchDistance = 6, enablePlaceholders = false),
            pagingSourceFactory = { GroupFeedPagingSource(groupsApi, groupId) },
        ).flow

    override suspend fun createGroupPost(
        groupId: String,
        text: String,
        imageUrls: List<String>,
        videoId: String?,
        unlockPriceCents: Int?,
    ): ApiResult<GroupFeedPost> = withContext(Dispatchers.IO) {
        call {
            groupsApi.createGroupPost(
                groupId,
                GroupPostCreateIn(
                    text = text,
                    imageUrl = imageUrls.firstOrNull(),
                    imageUrls = imageUrls.ifEmpty { null },
                    videoId = videoId?.takeIf { it.isNotBlank() },
                    unlockPriceCents = unlockPriceCents?.takeIf { it > 0 },
                ),
            ).toDomain()
        }
    }

    override suspend fun listComments(
        groupId: String,
        postId: String,
        cursor: String?,
        limit: Int,
    ): ApiResult<GroupCommentsPage> = withContext(Dispatchers.IO) {
        call {
            val out = groupsApi.getGroupComments(groupId, postId, cursor = cursor, limit = limit)
            GroupCommentsPage(
                comments = out.comments.map { it.toDomain() },
                nextCursor = out.nextCursor?.takeIf { it.isNotBlank() },
            )
        }
    }

    override suspend fun addComment(
        groupId: String,
        postId: String,
        text: String?,
        imageUrl: String?,
        parentCommentId: String?,
    ): ApiResult<GroupComment> = withContext(Dispatchers.IO) {
        call {
            groupsApi.addGroupComment(
                groupId,
                postId,
                GroupCommentCreateIn(
                    text = text?.takeIf { it.isNotBlank() },
                    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
                    parentCommentId = parentCommentId,
                ),
            ).toDomain()
        }
    }

    override suspend fun deleteComment(
        groupId: String,
        postId: String,
        commentId: String,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call { groupsApi.deleteGroupComment(groupId, postId, commentId).requireSuccess() }
    }

    override suspend fun invite(groupId: String, userId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { groupsApi.invite(groupId, GroupInviteIn(userId = userId)).requireSuccess() }
        }

    override suspend fun changeRole(
        groupId: String,
        userId: String,
        role: GroupRole,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            // admin is NOT assignable here; the wire token is one of moderator|member.
            val token = role.wire?.takeIf { role != GroupRole.ADMIN } ?: GroupRole.MEMBER.wire!!
            groupsApi.changeRole(groupId, userId, GroupUpdateRoleIn(role = token)).requireSuccess()
        }
    }

    override suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { groupsApi.removeMember(groupId, userId).requireSuccess() }
        }

    override suspend fun leave(groupId: String): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call { groupsApi.leave(groupId).requireSuccess() }
    }

    override suspend fun getTreasuryBalance(groupId: String): ApiResult<TreasuryBalance> =
        withContext(Dispatchers.IO) {
            call { groupsApi.getTreasuryBalance(groupId).toDomain() }
        }

    override suspend fun getTreasuryLedger(groupId: String): ApiResult<List<TreasuryLedgerEntry>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.getTreasuryLedger(groupId).entries.map { it.toDomain() } }
        }

    override suspend fun getTreasuryContributors(groupId: String): ApiResult<List<Contributor>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.getTreasuryContributors(groupId).contributors.map { it.toDomain() } }
        }

    override suspend fun listFundraisers(groupId: String): ApiResult<List<GroupFundraiser>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.listFundraisers(groupId).fundraisers.map { it.toDomain() } }
        }

    override suspend fun createFundraiser(
        groupId: String,
        title: String,
        description: String?,
        goalCents: Long?,
    ): ApiResult<GroupFundraiser> = withContext(Dispatchers.IO) {
        call {
            groupsApi.createFundraiser(
                groupId,
                GroupCreateFundraiserIn(
                    title = title,
                    description = description?.takeIf { it.isNotBlank() },
                    goalCents = goalCents,
                ),
            ).toDomain()
        }
    }

    override suspend fun listCampaigns(groupId: String): ApiResult<List<GroupCampaign>> =
        withContext(Dispatchers.IO) {
            call { groupsApi.listCampaigns(groupId).campaigns.map { it.toDomain() } }
        }

    override suspend fun getCampaignStats(
        groupId: String,
        campaignId: String,
    ): ApiResult<GroupCampaignStats> = withContext(Dispatchers.IO) {
        call { groupsApi.getCampaignStats(groupId, campaignId).toDomain() }
    }

    override suspend fun createCampaign(
        groupId: String,
        name: String,
        dailyBudgetCents: Long,
        lifetimeBudgetCents: Long,
        creativeText: String?,
    ): ApiResult<GroupCampaign> = withContext(Dispatchers.IO) {
        call {
            groupsApi.createCampaign(
                groupId,
                GroupCreateCampaignIn(
                    name = name,
                    dailyBudgetCents = dailyBudgetCents,
                    lifetimeBudgetCents = lifetimeBudgetCents,
                    creativeText = creativeText?.takeIf { it.isNotBlank() },
                ),
            ).toDomain()
        }
    }

    override suspend fun updateGroup(
        groupId: String,
        name: String?,
        description: String?,
        visibility: String?,
        topic: String?,
    ): ApiResult<Group> = withContext(Dispatchers.IO) {
        call {
            groupsApi.updateGroup(
                groupId,
                GroupUpdateIn(
                    name = name,
                    description = description,
                    visibility = visibility,
                    topic = topic,
                ),
            ).toDomain()
        }
    }

    /**
     * Folds an empty-body [Response] into Unit by HTTP success. A non-2xx response is rethrown as an
     * [HttpException] so [call] maps it to a Failure with the preserved status (mirrors how the typed
     * DTO calls surface errors).
     */
    private fun Response<Unit>.requireSuccess() {
        if (!isSuccessful) throw HttpException(this)
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-353.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

/** Batch-9 (#11) - one page of group post comments (mapped) + the opaque next cursor (null = end). */
data class GroupCommentsPage(
    val comments: List<GroupComment>,
    val nextCursor: String?,
)
