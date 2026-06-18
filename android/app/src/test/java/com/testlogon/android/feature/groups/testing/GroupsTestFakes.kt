package com.testlogon.android.feature.groups.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.groups.Contributor
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupCampaign
import com.testlogon.android.core.model.groups.GroupCampaignStats
import com.testlogon.android.core.model.groups.GroupFundraiser
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.model.groups.TreasuryBalance
import com.testlogon.android.core.model.groups.TreasuryLedgerEntry
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.groups.data.GroupsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * AND-355 - shared in-memory fakes for the groups ViewModel tests. Mutating calls RECORD their args BEFORE
 * honouring a configured failure. Helper / recording names are distinct and never shadow an interface
 * method.
 */
class FakeGroupsRepo(
    var myGroupsResult: ApiResult<List<Group>> = ApiResult.Success(emptyList()),
    var groupResult: ApiResult<Group> = ApiResult.Success(Group(id = "grp_1", name = "G")),
    var membersResult: ApiResult<List<GroupMember>> = ApiResult.Success(emptyList()),
    var inviteResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var changeRoleResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var removeResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var leaveResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var treasuryBalanceResult: ApiResult<TreasuryBalance> = ApiResult.Success(EMPTY_TREASURY_BALANCE),
    var treasuryLedgerResult: ApiResult<List<TreasuryLedgerEntry>> = ApiResult.Success(emptyList()),
    var treasuryContributorsResult: ApiResult<List<Contributor>> = ApiResult.Success(emptyList()),
    var fundraisersResult: ApiResult<List<GroupFundraiser>> = ApiResult.Success(emptyList()),
    var createFundraiserResult: ApiResult<GroupFundraiser> = ApiResult.Success(EMPTY_FUNDRAISER),
    var campaignsResult: ApiResult<List<GroupCampaign>> = ApiResult.Success(emptyList()),
    var campaignStatsResult: ApiResult<GroupCampaignStats> = ApiResult.Success(EMPTY_CAMPAIGN_STATS),
    var createCampaignResult: ApiResult<GroupCampaign> = ApiResult.Success(EMPTY_CAMPAIGN),
    var updateGroupResult: ApiResult<Group> = ApiResult.Success(Group(id = "grp_1", name = "G")),
) : GroupsRepository {

    val inviteArgs = mutableListOf<Pair<String, String>>()
    val changeRoleArgs = mutableListOf<Triple<String, String, GroupRole>>()
    val removeArgs = mutableListOf<Pair<String, String>>()
    val leaveArgs = mutableListOf<String>()
    val createFundraiserArgs = mutableListOf<CreateFundraiserArgs>()
    val createCampaignArgs = mutableListOf<CreateCampaignArgs>()
    val updateGroupArgs = mutableListOf<UpdateGroupArgs>()

    /** When set, the roster returned by [listMembers] after the first call (used to test invite re-fetch). */
    var membersAfterInvite: ApiResult<List<GroupMember>>? = null
    private var membersCallCount = 0

    override suspend fun listMyGroups(): ApiResult<List<Group>> = myGroupsResult

    override suspend fun getGroup(groupId: String): ApiResult<Group> = groupResult

    override suspend fun listMembers(groupId: String): ApiResult<List<GroupMember>> {
        membersCallCount++
        val after = membersAfterInvite
        return if (after != null && membersCallCount > 1) after else membersResult
    }

    override suspend fun invite(groupId: String, userId: String): ApiResult<Unit> {
        inviteArgs += groupId to userId
        return inviteResult
    }

    override suspend fun changeRole(
        groupId: String,
        userId: String,
        role: GroupRole,
    ): ApiResult<Unit> {
        changeRoleArgs += Triple(groupId, userId, role)
        return changeRoleResult
    }

    override suspend fun removeMember(groupId: String, userId: String): ApiResult<Unit> {
        removeArgs += groupId to userId
        return removeResult
    }

    override suspend fun leave(groupId: String): ApiResult<Unit> {
        leaveArgs += groupId
        return leaveResult
    }

    override suspend fun getTreasuryBalance(groupId: String): ApiResult<TreasuryBalance> =
        treasuryBalanceResult

    override suspend fun getTreasuryLedger(groupId: String): ApiResult<List<TreasuryLedgerEntry>> =
        treasuryLedgerResult

    override suspend fun getTreasuryContributors(groupId: String): ApiResult<List<Contributor>> =
        treasuryContributorsResult

    override suspend fun listFundraisers(groupId: String): ApiResult<List<GroupFundraiser>> =
        fundraisersResult

    override suspend fun createFundraiser(
        groupId: String,
        title: String,
        description: String?,
        goalCents: Long?,
    ): ApiResult<GroupFundraiser> {
        createFundraiserArgs += CreateFundraiserArgs(groupId, title, description, goalCents)
        return createFundraiserResult
    }

    override suspend fun listCampaigns(groupId: String): ApiResult<List<GroupCampaign>> =
        campaignsResult

    override suspend fun getCampaignStats(
        groupId: String,
        campaignId: String,
    ): ApiResult<GroupCampaignStats> = campaignStatsResult

    override suspend fun createCampaign(
        groupId: String,
        name: String,
        dailyBudgetCents: Long,
        lifetimeBudgetCents: Long,
        creativeText: String?,
    ): ApiResult<GroupCampaign> {
        createCampaignArgs += CreateCampaignArgs(
            groupId, name, dailyBudgetCents, lifetimeBudgetCents, creativeText,
        )
        return createCampaignResult
    }

    override suspend fun updateGroup(
        groupId: String,
        name: String?,
        description: String?,
        visibility: String?,
        topic: String?,
    ): ApiResult<Group> {
        updateGroupArgs += UpdateGroupArgs(groupId, name, description, visibility, topic)
        return updateGroupResult
    }

    data class CreateFundraiserArgs(
        val groupId: String,
        val title: String,
        val description: String?,
        val goalCents: Long?,
    )

    data class CreateCampaignArgs(
        val groupId: String,
        val name: String,
        val dailyBudgetCents: Long,
        val lifetimeBudgetCents: Long,
        val creativeText: String?,
    )

    data class UpdateGroupArgs(
        val groupId: String,
        val name: String?,
        val description: String?,
        val visibility: String?,
        val topic: String?,
    )

    companion object {
        fun failure(status: Int = 422, code: String? = null): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom", code = code))

        private val EMPTY_TREASURY_BALANCE = TreasuryBalance(
            balanceCents = 0L,
            currency = "USD",
            totalContributedCents = 0L,
            totalDonatedCents = 0L,
            totalSpentCents = 0L,
            fundraisingGoalCents = null,
        )

        private val EMPTY_FUNDRAISER = GroupFundraiser(
            fundraiserId = "fr_1",
            title = "F",
            description = null,
            goalCents = null,
            raisedCents = 0L,
            donationCount = 0,
            currency = "USD",
            status = "active",
            coverImageUrl = null,
            createdAt = null,
            endsAt = null,
        )

        private val EMPTY_CAMPAIGN = GroupCampaign(
            campaignId = "cmp_1",
            name = "C",
            status = "active",
            dailyBudgetCents = 0L,
            lifetimeBudgetCents = 0L,
            spentCents = 0L,
            impressions = 0L,
            clicks = 0L,
            creativeText = null,
            creativeImageUrl = null,
            createdAt = null,
        )

        private val EMPTY_CAMPAIGN_STATS = GroupCampaignStats(
            campaignId = "cmp_1",
            impressions = 0L,
            clicks = 0L,
            ctr = 0.0,
            spentCents = 0L,
            remainingCents = 0L,
            dailySpentCents = 0L,
            dailyBudgetCents = 0L,
            status = "active",
        )
    }
}

/** A fake AuthStateStore exposing a fixed viewer user_id (distinct from the orgs-package fake). */
class FakeGroupsAuthStore(viewerId: String?) : AuthStateStore {
    private val sub = MutableStateFlow(viewerId)
    override val userSub: StateFlow<String?> = sub.asStateFlow()
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(viewerId != null).asStateFlow()
    override suspend fun setAuthenticated(userSub: String) {
        sub.value = userSub
    }
    override suspend fun clear(reason: LogoutReason) {
        sub.value = null
    }
    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}
