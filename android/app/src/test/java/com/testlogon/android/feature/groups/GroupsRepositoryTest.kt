package com.testlogon.android.feature.groups

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.groups.GroupListResponse
import com.testlogon.android.core.network.groups.GroupMemberDto
import com.testlogon.android.core.network.groups.GroupMembersResponse
import com.testlogon.android.core.network.groups.UserGroupDto
import com.testlogon.android.feature.groups.data.GroupsRepositoryImpl
import com.testlogon.android.feature.groups.testing.FakeGroupsApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-355 - unit tests for [GroupsRepositoryImpl]: ENVELOPE unwrap + DTO -> domain mapping (role parse +
 * status kept raw + invited=pending), the empty-200 -> Success(Unit) success-by-isSuccessful path, the
 * admin-not-assignable role sanitization, and HttpException -> Failure. Uses the FAKE GroupsApi (no
 * Moshi); the [ApiErrorParser] needs only a Map adapter so a plain Moshi suffices.
 */
class GroupsRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeGroupsApi) = GroupsRepositoryImpl(api, errorParser)

    @Test
    fun listMyGroups_unwrapsEnvelope_andParsesRole() = runTest {
        val api = FakeGroupsApi(
            groupsEnvelope = GroupListResponse(
                groups = listOf(
                    UserGroupDto(groupId = "grp_1", name = "Hikers", myRole = "admin"),
                    UserGroupDto(groupId = "grp_2", name = "Readers", myRole = "weird"),
                ),
            ),
        )
        val result = repo(api).listMyGroups()
        assertTrue(result is ApiResult.Success)
        val groups = (result as ApiResult.Success).data
        assertEquals(2, groups.size)
        assertEquals(GroupRole.ADMIN, groups[0].myRole)
        // unknown wire role -> UNKNOWN (never throws)
        assertEquals(GroupRole.UNKNOWN, groups[1].myRole)
    }

    @Test
    fun listMembers_unwrapsEnvelope_keepsStatusRaw_andMarksPending() = runTest {
        val api = FakeGroupsApi(
            membersEnvelope = GroupMembersResponse(
                members = listOf(
                    GroupMemberDto(userId = "usr_a", role = "moderator", status = "active"),
                    GroupMemberDto(userId = "usr_b", role = "member", status = "invited"),
                ),
                count = 2,
            ),
        )
        val result = repo(api).listMembers("grp_1")
        assertTrue(result is ApiResult.Success)
        val members = (result as ApiResult.Success).data
        assertEquals(GroupRole.MODERATOR, members[0].role)
        assertEquals("active", members[0].status)
        // invited status is kept raw and flags a pending entry
        assertEquals("invited", members[1].status)
        assertTrue(members[1].isPending)
    }

    @Test
    fun getGroup_mapsDetail() = runTest {
        val api = FakeGroupsApi(
            groupDetail = UserGroupDto(
                groupId = "grp_1",
                name = "Hikers",
                description = "trails",
                memberCount = 5,
                myRole = "member",
                adminUserId = "usr_admin",
            ),
        )
        val result = repo(api).getGroup("grp_1")
        assertTrue(result is ApiResult.Success)
        val group = (result as ApiResult.Success).data
        assertEquals("Hikers", group.name)
        assertEquals(5, group.memberCount)
        assertEquals(GroupRole.MEMBER, group.myRole)
        assertEquals("usr_admin", group.adminUserId)
    }

    @Test
    fun invite_sendsUserId_empty200_isSuccessUnit() = runTest {
        val api = FakeGroupsApi()
        val result = repo(api).invite("grp_1", "usr_new")
        assertTrue(result is ApiResult.Success)
        assertEquals("grp_1" to "usr_new", api.inviteBodies.single().let { it.first to it.second.userId })
    }

    @Test
    fun changeRole_sendsModeratorToken_empty200_isSuccessUnit() = runTest {
        val api = FakeGroupsApi()
        val result = repo(api).changeRole("grp_1", "usr_a", GroupRole.MODERATOR)
        assertTrue(result is ApiResult.Success)
        assertEquals("moderator", api.changeRoleCalls.single().third.role)
    }

    @Test
    fun changeRole_adminRole_isCoercedToMember_neverAdmin() = runTest {
        val api = FakeGroupsApi()
        repo(api).changeRole("grp_1", "usr_a", GroupRole.ADMIN)
        // admin is NOT assignable -> the sent token falls back to member
        assertEquals("member", api.changeRoleCalls.single().third.role)
    }

    @Test
    fun removeMember_empty200_isSuccessUnit() = runTest {
        val api = FakeGroupsApi()
        val result = repo(api).removeMember("grp_1", "usr_a")
        assertTrue(result is ApiResult.Success)
        assertEquals("grp_1" to "usr_a", api.removeCalls.single())
    }

    @Test
    fun leave_empty200_isSuccessUnit() = runTest {
        val api = FakeGroupsApi()
        val result = repo(api).leave("grp_1")
        assertTrue(result is ApiResult.Success)
        assertEquals("grp_1", api.leaveCalls.single())
    }

    @Test
    fun httpError_mapsToFailure_preservingStatus() = runTest {
        val api = FakeGroupsApi(throwHttp = 403)
        val result = repo(api).listMembers("grp_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun removeMember_httpError_recordedBeforeFailure() = runTest {
        val api = FakeGroupsApi(throwHttp = 422)
        val result = repo(api).removeMember("grp_1", "usr_a")
        assertTrue(result is ApiResult.Failure)
        // the call was recorded BEFORE the throw
        assertEquals("grp_1" to "usr_a", api.removeCalls.single())
    }

    @Test
    fun leave_httpError_recordedBeforeFailure() = runTest {
        val api = FakeGroupsApi(throwHttp = 409)
        val result = repo(api).leave("grp_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(409, (result as ApiResult.Failure).error.status)
        assertEquals("grp_1", api.leaveCalls.single())
    }
}
