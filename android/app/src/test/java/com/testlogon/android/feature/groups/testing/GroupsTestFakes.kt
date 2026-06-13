package com.testlogon.android.feature.groups.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
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
) : GroupsRepository {

    val inviteArgs = mutableListOf<Pair<String, String>>()
    val changeRoleArgs = mutableListOf<Triple<String, String, GroupRole>>()
    val removeArgs = mutableListOf<Pair<String, String>>()
    val leaveArgs = mutableListOf<String>()

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

    companion object {
        fun failure(status: Int = 422, code: String? = null): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom", code = code))
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
