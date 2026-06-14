package com.testlogon.android.feature.groups.testing

import com.testlogon.android.core.network.groups.GroupInviteIn
import com.testlogon.android.core.network.groups.GroupListResponse
import com.testlogon.android.core.network.groups.GroupMembersResponse
import com.testlogon.android.core.network.groups.GroupUpdateRoleIn
import com.testlogon.android.core.network.groups.GroupsApi
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
    var throwHttp: Int? = null,
) : GroupsApi {

    val inviteBodies = mutableListOf<Pair<String, GroupInviteIn>>()
    val changeRoleCalls = mutableListOf<Triple<String, String, GroupUpdateRoleIn>>()
    val removeCalls = mutableListOf<Pair<String, String>>()
    val leaveCalls = mutableListOf<String>()

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

    override suspend fun listMyGroups(): GroupListResponse {
        maybeThrow()
        return groupsEnvelope
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
}
