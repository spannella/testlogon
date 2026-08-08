package com.testlogon.android.feature.orgs.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.orgs.data.OrgsRepository
import com.testlogon.android.feature.orgs.data.SelectedOrgStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first

/**
 * AND-353 - shared in-memory fakes for the [com.testlogon.android.feature.orgs.OrgMembersViewModel]
 * tests. Mutating calls RECORD their args BEFORE honouring a configured failure. Helper / recording names
 * are distinct and never shadow an interface method.
 */
class FakeOrgsRepo(
    var orgsResult: ApiResult<List<Org>> = ApiResult.Success(emptyList()),
    var membersResult: ApiResult<List<OrgMember>> = ApiResult.Success(emptyList()),
    var invitesResult: ApiResult<List<OrgInvite>> = ApiResult.Success(emptyList()),
    var inviteResult: ApiResult<OrgInvite> =
        ApiResult.Success(OrgInvite(inviteId = "inv_new", email = "new@x.com", role = OrgRole.MEMBER)),
    var changeRoleResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var removeResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var transferResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var leaveResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var acceptResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var declineResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : OrgsRepository {

    val changeRoleArgs = mutableListOf<Triple<String, String, OrgRole>>()
    val removeArgs = mutableListOf<Pair<String, String>>()
    val inviteArgs = mutableListOf<Triple<String, String, OrgRole?>>()
    val acceptArgs = mutableListOf<Pair<String, String>>()
    val declineArgs = mutableListOf<String>()

    override suspend fun listOrgs(): ApiResult<List<Org>> = orgsResult
    override suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>> = membersResult
    override suspend fun listPendingInvites(): ApiResult<List<OrgInvite>> = invitesResult

    override suspend fun inviteMember(
        orgId: String,
        email: String,
        role: OrgRole?,
    ): ApiResult<OrgInvite> {
        inviteArgs += Triple(orgId, email, role)
        return inviteResult
    }

    override suspend fun changeRole(
        orgId: String,
        memberSub: String,
        role: OrgRole,
    ): ApiResult<Unit> {
        changeRoleArgs += Triple(orgId, memberSub, role)
        return changeRoleResult
    }

    override suspend fun removeMember(orgId: String, memberSub: String): ApiResult<Unit> {
        removeArgs += orgId to memberSub
        return removeResult
    }

    override suspend fun transferOwnership(orgId: String, newOwnerUserSub: String): ApiResult<Unit> {
        transferArgs += orgId to newOwnerUserSub
        return transferResult
    }

    val transferArgs = mutableListOf<Pair<String, String>>()
    val leaveArgs = mutableListOf<String>()
    override suspend fun leaveOrg(orgId: String): ApiResult<Unit> {
        leaveArgs += orgId
        return leaveResult
    }

    override suspend fun acceptInvite(inviteId: String, token: String): ApiResult<Unit> {
        acceptArgs += inviteId to token
        return acceptResult
    }

    override suspend fun declineInvite(inviteId: String): ApiResult<Unit> {
        declineArgs += inviteId
        return declineResult
    }

    companion object {
        fun failure(status: Int = 422): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}

/** A fake selected-org store backed by a single mutable value. */
class FakeSelectedOrgStore(initial: String? = null) : SelectedOrgStore {
    private val state = MutableStateFlow(initial)
    val storedId: String? get() = state.value
    override val selectedOrgId: Flow<String?> get() = state
    override suspend fun setSelectedOrgId(orgId: String) {
        state.value = orgId
    }
    suspend fun current(): String? = selectedOrgId.first()
}

/** A fake AuthStateStore exposing a fixed caller user_sub. */
class FakeAuthStateStore(callerSub: String?) : AuthStateStore {
    private val sub = MutableStateFlow(callerSub)
    override val userSub: StateFlow<String?> = sub.asStateFlow()
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(callerSub != null).asStateFlow()
    override suspend fun setAuthenticated(userSub: String) {
        sub.value = userSub
    }
    override suspend fun clear(reason: LogoutReason) {
        sub.value = null
    }
    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}
