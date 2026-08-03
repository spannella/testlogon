package com.testlogon.android.feature.groups.testing

import com.testlogon.android.core.network.groups.ContributorListResponse
import com.testlogon.android.core.network.groups.GroupCampaignDto
import com.testlogon.android.core.network.groups.GroupCampaignListResponse
import com.testlogon.android.core.network.groups.GroupCampaignStatsDto
import com.testlogon.android.core.network.groups.GroupCreateCampaignIn
import com.testlogon.android.core.network.groups.GroupCreateIn
import com.testlogon.android.core.network.groups.GroupDiscoverResponse
import com.testlogon.android.core.network.groups.GroupCreateFundraiserIn
import com.testlogon.android.core.network.groups.GroupFundraiserDto
import com.testlogon.android.core.network.groups.GroupCommentCreateIn
import com.testlogon.android.core.network.groups.GroupCommentDto
import com.testlogon.android.core.network.groups.GroupCommentListResponse
import com.testlogon.android.core.network.groups.GroupFeedPostDto
import com.testlogon.android.core.network.groups.GroupFeedResponse
import com.testlogon.android.core.network.groups.GroupPostCreateIn
import com.testlogon.android.core.network.groups.GroupFundraiserListResponse
import com.testlogon.android.core.network.groups.GroupInviteIn
import com.testlogon.android.core.network.groups.GroupListResponse
import com.testlogon.android.core.network.groups.GroupMembersResponse
import com.testlogon.android.core.network.groups.GroupUpdateIn
import com.testlogon.android.core.network.groups.GroupUpdateRoleIn
import com.testlogon.android.core.network.groups.GroupsApi
import com.testlogon.android.core.network.groups.TreasuryBalanceDto
import com.testlogon.android.core.network.groups.TreasuryLedgerResponse
import com.testlogon.android.core.network.groups.UserGroupDto
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-355 - an in-memory fake of [GroupsApi] for :app repository tests (NO Moshi).
 *
 * The mutating calls RECORD their args BEFORE honouring a configured throw, so a test can assert the call
 * happened even on the failure path. Recording / helper names are distinct and never shadow an interface
 * method. Configure [throwHttp] to make the next call throw an [HttpException] with that status.
 */
class FakeGroupsApi(
    var groupsEnvelope: GroupListResponse = GroupListResponse(),
    var groupDetail: UserGroupDto = UserGroupDto(groupId = "grp_1", name = "G"),
    var membersEnvelope: GroupMembersResponse = GroupMembersResponse(),
    var treasuryBalance: TreasuryBalanceDto = TreasuryBalanceDto(balanceCents = 0L),
    var treasuryLedger: TreasuryLedgerResponse = TreasuryLedgerResponse(),
    var contributorsEnvelope: ContributorListResponse = ContributorListResponse(),
    var fundraisersEnvelope: GroupFundraiserListResponse = GroupFundraiserListResponse(),
    var fundraiserDetail: GroupFundraiserDto = GroupFundraiserDto(fundraiserId = "fr_1", title = "F"),
    var campaignsEnvelope: GroupCampaignListResponse = GroupCampaignListResponse(),
    var campaignDetail: GroupCampaignDto = GroupCampaignDto(campaignId = "cmp_1", name = "C"),
    var campaignStats: GroupCampaignStatsDto = GroupCampaignStatsDto(campaignId = "cmp_1"),
    var feedEnvelope: GroupFeedResponse = GroupFeedResponse(),
    var feedPostDetail: GroupFeedPostDto = GroupFeedPostDto(postId = "gp_1"),
    var commentsEnvelope: GroupCommentListResponse = GroupCommentListResponse(),
    var commentDetail: GroupCommentDto = GroupCommentDto(commentId = "gc_1", userId = "usr_1"),
    var discoverEnvelope: GroupDiscoverResponse = GroupDiscoverResponse(),
    var throwHttp: Int? = null,
) : GroupsApi {

    val inviteBodies = mutableListOf<Pair<String, GroupInviteIn>>()
    val changeRoleCalls = mutableListOf<Triple<String, String, GroupUpdateRoleIn>>()
    val removeCalls = mutableListOf<Pair<String, String>>()
    val leaveCalls = mutableListOf<String>()
    val createFundraiserCalls = mutableListOf<Pair<String, GroupCreateFundraiserIn>>()
    val createCampaignCalls = mutableListOf<Pair<String, GroupCreateCampaignIn>>()
    val updateGroupCalls = mutableListOf<Pair<String, GroupUpdateIn>>()
    val createGroupBodies = mutableListOf<GroupCreateIn>()

    private fun maybeThrow() {
        throwHttp?.let { status ->
            throw HttpException(
                Response.error<Any>(
                    status,
                    """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
                ),
            )
        }
    }

    private fun emptyOk(): Response<Unit> = Response.success(Unit)

    // B-GRPFULL: group feed posts + comments (added by the group-feed program).
    val createGroupPostBodies = mutableListOf<Pair<String, GroupPostCreateIn>>()
    val addGroupCommentBodies = mutableListOf<Triple<String, String, GroupCommentCreateIn>>()
    val deleteGroupCommentCalls = mutableListOf<Triple<String, String, String>>()

    override suspend fun createGroupPost(groupId: String, body: GroupPostCreateIn): GroupFeedPostDto {
        createGroupPostBodies += groupId to body
        maybeThrow()
        return feedPostDetail
    }

    override suspend fun getGroupFeed(groupId: String, cursor: String?, limit: Int): GroupFeedResponse {
        maybeThrow()
        return feedEnvelope
    }

    override suspend fun addGroupComment(
        groupId: String,
        postId: String,
        body: GroupCommentCreateIn,
    ): GroupCommentDto {
        addGroupCommentBodies += Triple(groupId, postId, body)
        maybeThrow()
        return commentDetail
    }

    override suspend fun getGroupComments(
        groupId: String,
        postId: String,
        cursor: String?,
        limit: Int,
    ): GroupCommentListResponse {
        maybeThrow()
        return commentsEnvelope
    }

    override suspend fun deleteGroupComment(
        groupId: String,
        postId: String,
        commentId: String,
    ): Response<Unit> {
        deleteGroupCommentCalls += Triple(groupId, postId, commentId)
        maybeThrow()
        return emptyOk()
    }

    override suspend fun listMyGroups(): GroupListResponse {
        maybeThrow()
        return groupsEnvelope
    }

    override suspend fun createGroup(body: GroupCreateIn): UserGroupDto {
        createGroupBodies += body
        maybeThrow()
        return groupDetail
    }

    override suspend fun getGroup(groupId: String): UserGroupDto {
        maybeThrow()
        return groupDetail
    }

    override suspend fun listMembers(groupId: String): GroupMembersResponse {
        maybeThrow()
        return membersEnvelope
    }

    override suspend fun invite(groupId: String, body: GroupInviteIn): Response<Unit> {
        inviteBodies += groupId to body
        maybeThrow()
        return emptyOk()
    }

    override suspend fun changeRole(
        groupId: String,
        userId: String,
        body: GroupUpdateRoleIn,
    ): Response<Unit> {
        changeRoleCalls += Triple(groupId, userId, body)
        maybeThrow()
        return emptyOk()
    }

    override suspend fun removeMember(groupId: String, userId: String): Response<Unit> {
        removeCalls += groupId to userId
        maybeThrow()
        return emptyOk()
    }

    override suspend fun leave(groupId: String): Response<Unit> {
        leaveCalls += groupId
        maybeThrow()
        return emptyOk()
    }

    val discoverQueries = mutableListOf<String?>()
    val joinCalls = mutableListOf<String>()

    override suspend fun discover(query: String?, limit: Int): GroupDiscoverResponse {
        discoverQueries += query
        maybeThrow()
        return discoverEnvelope
    }

    override suspend fun join(groupId: String): Response<Unit> {
        joinCalls += groupId
        maybeThrow()
        return emptyOk()
    }

    override suspend fun getTreasuryBalance(groupId: String): TreasuryBalanceDto {
        maybeThrow()
        return treasuryBalance
    }

    override suspend fun getTreasuryLedger(
        groupId: String,
        limit: Int?,
        cursor: String?,
    ): TreasuryLedgerResponse {
        maybeThrow()
        return treasuryLedger
    }

    override suspend fun getTreasuryContributors(groupId: String): ContributorListResponse {
        maybeThrow()
        return contributorsEnvelope
    }

    override suspend fun listFundraisers(groupId: String): GroupFundraiserListResponse {
        maybeThrow()
        return fundraisersEnvelope
    }

    override suspend fun createFundraiser(
        groupId: String,
        body: GroupCreateFundraiserIn,
    ): GroupFundraiserDto {
        createFundraiserCalls += groupId to body
        maybeThrow()
        return fundraiserDetail
    }

    override suspend fun listCampaigns(groupId: String): GroupCampaignListResponse {
        maybeThrow()
        return campaignsEnvelope
    }

    override suspend fun getCampaignStats(
        groupId: String,
        campaignId: String,
    ): GroupCampaignStatsDto {
        maybeThrow()
        return campaignStats
    }

    override suspend fun createCampaign(
        groupId: String,
        body: GroupCreateCampaignIn,
    ): GroupCampaignDto {
        createCampaignCalls += groupId to body
        maybeThrow()
        return campaignDetail
    }

    override suspend fun updateGroup(
        groupId: String,
        body: GroupUpdateIn,
    ): UserGroupDto {
        updateGroupCalls += groupId to body
        maybeThrow()
        return groupDetail
    }
}
