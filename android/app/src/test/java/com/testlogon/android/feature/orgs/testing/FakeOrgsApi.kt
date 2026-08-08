package com.testlogon.android.feature.orgs.testing

import com.testlogon.android.core.network.orgs.OrgInviteAcceptReq
import com.testlogon.android.core.network.orgs.OrgInviteOut
import com.testlogon.android.core.network.orgs.OrgMemberInviteReq
import com.testlogon.android.core.network.orgs.OrgMemberOut
import com.testlogon.android.core.network.orgs.OrgMemberRoleUpdateReq
import com.testlogon.android.core.network.orgs.OrgOut
import com.testlogon.android.core.network.orgs.OrgsApi
import com.testlogon.android.core.network.orgs.TransferOwnershipReq
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-353 - an in-memory fake of [OrgsApi] for :app repository tests (NO Moshi).
 *
 * The mutating calls RECORD their args BEFORE honouring a configured throw, so a test can assert the call
 * happened even on the failure path. Recording / helper names are distinct and never shadow an interface
 * method. Configure [throwHttp] to make the next call throw an [HttpException] with that status.
 */
class FakeOrgsApi(
    var orgs: List<OrgOut> = emptyList(),
    var members: List<OrgMemberOut> = emptyList(),
    var pendingInvites: List<OrgInviteOut> = emptyList(),
    var inviteResult: OrgInviteOut = OrgInviteOut(inviteId = "inv_new", email = "new@x.com"),
    var throwHttp: Int? = null,
) : OrgsApi {

    val inviteBodies = mutableListOf<Pair<String, OrgMemberInviteReq>>()
    val changeRoleCalls = mutableListOf<Triple<String, String, OrgMemberRoleUpdateReq>>()
    val removeCalls = mutableListOf<Pair<String, String>>()
    val transferCalls = mutableListOf<Pair<String, TransferOwnershipReq>>()
    val acceptCalls = mutableListOf<Pair<String, OrgInviteAcceptReq>>()
    val declineCalls = mutableListOf<String>()
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

    override suspend fun listOrgs(): List<OrgOut> {
        maybeThrow()
        return orgs
    }

    override suspend fun listMembers(orgId: String): List<OrgMemberOut> {
        maybeThrow()
        return members
    }

    override suspend fun listPendingInvites(): List<OrgInviteOut> {
        maybeThrow()
        return pendingInvites
    }

    override suspend fun inviteMember(orgId: String, body: OrgMemberInviteReq): OrgInviteOut {
        inviteBodies += orgId to body
        maybeThrow()
        return inviteResult
    }

    override suspend fun changeRole(
        orgId: String,
        memberSub: String,
        body: OrgMemberRoleUpdateReq,
    ): Response<Unit> {
        changeRoleCalls += Triple(orgId, memberSub, body)
        maybeThrow()
        return emptyOk()
    }

    override suspend fun removeMember(orgId: String, memberSub: String): Response<Unit> {
        removeCalls += orgId to memberSub
        maybeThrow()
        return emptyOk()
    }

    override suspend fun transferOwnership(
        orgId: String,
        body: TransferOwnershipReq,
    ): Response<Unit> {
        transferCalls += orgId to body
        maybeThrow()
        return emptyOk()
    }

    override suspend fun acceptInvite(inviteId: String, body: OrgInviteAcceptReq): Response<Unit> {
        acceptCalls += inviteId to body
        maybeThrow()
        return emptyOk()
    }

    override suspend fun declineInvite(inviteId: String): Response<Unit> {
        declineCalls += inviteId
        maybeThrow()
        return emptyOk()
    }

    override suspend fun leaveOrg(orgId: String): Response<Unit> {
        leaveCalls += orgId
        maybeThrow()
        return emptyOk()
    }
}
