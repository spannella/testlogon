package com.testlogon.android.feature.orgs

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.orgs.OrgInviteOut
import com.testlogon.android.core.network.orgs.OrgMemberOut
import com.testlogon.android.core.network.orgs.OrgOut
import com.testlogon.android.feature.orgs.data.OrgsRepositoryImpl
import com.testlogon.android.feature.orgs.testing.FakeOrgsApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-353 - unit tests for [OrgsRepositoryImpl]: DTO -> domain mapping (incl. org_role parse + status
 * kept raw), the empty-204 / empty-200 -> Success(Unit) success-by-isSuccessful path, owner-not-invitable
 * sanitization, and HttpException -> Failure. Uses the FAKE OrgsApi (no Moshi); the [ApiErrorParser]
 * needs only a Map adapter so a plain Moshi (no KotlinJsonAdapterFactory) suffices.
 */
class OrgsRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: FakeOrgsApi) = OrgsRepositoryImpl(api, errorParser)

    @Test
    fun listOrgs_mapsDtoToDomain_parsingCallerRole() = runTest {
        val api = FakeOrgsApi(
            orgs = listOf(
                OrgOut(orgId = "org_1", orgName = "Acme", orgRole = "admin"),
                OrgOut(orgId = "org_2", orgRole = "weird-role"),
            ),
        )
        val result = repo(api).listOrgs()
        assertTrue(result is ApiResult.Success)
        val orgs = (result as ApiResult.Success).data
        assertEquals(OrgRole.ADMIN, orgs[0].callerRole)
        // unknown wire role -> UNKNOWN (never throws)
        assertEquals(OrgRole.UNKNOWN, orgs[1].callerRole)
    }

    @Test
    fun listMembers_mapsRole_andKeepsStatusRaw() = runTest {
        val api = FakeOrgsApi(
            members = listOf(
                OrgMemberOut(userSub = "usr_a", orgRole = "owner", status = "invited_seat_pending"),
            ),
        )
        val result = repo(api).listMembers("org_1")
        assertTrue(result is ApiResult.Success)
        val member = (result as ApiResult.Success).data.single()
        assertEquals(OrgRole.OWNER, member.role)
        // status is passed through verbatim (no enum coercion)
        assertEquals("invited_seat_pending", member.status)
    }

    @Test
    fun inviteMember_sendsRoleToken_andMapsPendingInvite() = runTest {
        val api = FakeOrgsApi(
            inviteResult = OrgInviteOut(inviteId = "inv_9", email = "n@x.com", orgRole = "viewer"),
        )
        val result = repo(api).inviteMember("org_1", "n@x.com", OrgRole.VIEWER)
        assertTrue(result is ApiResult.Success)
        assertEquals("inv_9", (result as ApiResult.Success).data.inviteId)
        assertEquals("org_1" to "n@x.com", api.inviteBodies.single().let { it.first to it.second.email })
        assertEquals("viewer", api.inviteBodies.single().second.orgRole)
    }

    @Test
    fun inviteMember_ownerRole_isNotSent_asOwner() = runTest {
        val api = FakeOrgsApi()
        repo(api).inviteMember("org_1", "n@x.com", OrgRole.OWNER)
        // owner is NOT invitable -> the role token is dropped (null -> server default)
        assertEquals(null, api.inviteBodies.single().second.orgRole)
    }

    @Test
    fun changeRole_empty200_isSuccessUnit() = runTest {
        val api = FakeOrgsApi()
        val result = repo(api).changeRole("org_1", "usr_a", OrgRole.ADMIN)
        assertTrue(result is ApiResult.Success)
        assertEquals("admin", api.changeRoleCalls.single().third.orgRole)
    }

    @Test
    fun removeMember_empty204_isSuccessUnit() = runTest {
        val api = FakeOrgsApi()
        val result = repo(api).removeMember("org_1", "usr_a")
        assertTrue(result is ApiResult.Success)
        assertEquals("org_1" to "usr_a", api.removeCalls.single())
    }

    @Test
    fun transferOwnership_empty200_isSuccessUnit() = runTest {
        val api = FakeOrgsApi()
        val result = repo(api).transferOwnership("org_1", "usr_b")
        assertTrue(result is ApiResult.Success)
        assertEquals("usr_b", api.transferCalls.single().second.newOwnerUserSub)
    }

    @Test
    fun httpError_mapsToFailure_preservingStatus() = runTest {
        val api = FakeOrgsApi(throwHttp = 403)
        val result = repo(api).listMembers("org_1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(403, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun removeMember_httpError_recordedBeforeFailure() = runTest {
        val api = FakeOrgsApi(throwHttp = 422)
        val result = repo(api).removeMember("org_1", "usr_a")
        assertTrue(result is ApiResult.Failure)
        // the call was recorded BEFORE the throw
        assertEquals("org_1" to "usr_a", api.removeCalls.single())
    }
}
