package com.testlogon.android.feature.orgs.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.orgs.OrgInviteAcceptReq
import com.testlogon.android.core.network.orgs.OrgMemberInviteReq
import com.testlogon.android.core.network.orgs.OrgMemberRoleUpdateReq
import com.testlogon.android.core.network.orgs.OrgsApi
import com.testlogon.android.core.network.orgs.TransferOwnershipReq
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-353 - data layer for the organizations members/roles surface.
 *
 * REUSE: every call REUSES AND-353's [OrgsApi] (which returns RAW DTOs / Response<Unit>); this repository
 * wraps each call in [call] and maps the DTO to the core-model domain BEFORE the typed [ApiResult]
 * (mirrors AND-340 SignatureRepository). The empty-body 204 (DELETE) and the possibly-empty 200 (PATCH /
 * transfer) are treated as success-by-isSuccessful -> ApiResult.Success(Unit).
 *
 * There is NO Room / disk persistence (no migration) and NO poll loop here.
 */
interface OrgsRepository {

    /** GET all orgs the caller belongs to (mapped). Idempotent GET. */
    suspend fun listOrgs(): ApiResult<List<Org>>

    /** GET one org's member roster (mapped). Idempotent GET. */
    suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>>

    /** GET the caller's pending invites (mapped). Idempotent GET. */
    suspend fun listPendingInvites(): ApiResult<List<OrgInvite>>

    /**
     * POST an invite. On 201 returns the created PENDING [OrgInvite] (NOT a member). [role] is optional
     * (server default "member"); owner is NOT invitable.
     */
    suspend fun inviteMember(orgId: String, email: String, role: OrgRole?): ApiResult<OrgInvite>

    /** PATCH a member's role (admin|member|viewer only). 200/empty -> Success(Unit). */
    suspend fun changeRole(orgId: String, memberSub: String, role: OrgRole): ApiResult<Unit>

    /** DELETE a member. 204 empty -> Success(Unit). */
    suspend fun removeMember(orgId: String, memberSub: String): ApiResult<Unit>

    /** POST ownership transfer (the separate owner-assignment endpoint). 200/204 -> Success(Unit). */
    suspend fun transferOwnership(orgId: String, newOwnerUserSub: String): ApiResult<Unit>

    /**
     * PAR-35(b) - the caller LEAVES the org. 204 empty -> Success(Unit). A sole-owner leave is rejected by
     * the backend with 409 -> Failure(status=409) (the caller surfaces a "transfer ownership first" hint).
     */
    suspend fun leaveOrg(orgId: String): ApiResult<Unit>

    /**
     * AND-354 - the caller ACCEPTS one of their own pending invites. [token] is the per-invite token (or
     * empty when the wire row omits one). Success-by-isSuccessful -> Success(Unit).
     */
    suspend fun acceptInvite(inviteId: String, token: String): ApiResult<Unit>

    /** AND-354 - the caller DECLINES one of their own pending invites. 204 empty -> Success(Unit). */
    suspend fun declineInvite(inviteId: String): ApiResult<Unit>
}

@Singleton
class OrgsRepositoryImpl @Inject constructor(
    private val orgsApi: OrgsApi,
    private val errorParser: ApiErrorParser,
) : OrgsRepository {

    override suspend fun listOrgs(): ApiResult<List<Org>> = withContext(Dispatchers.IO) {
        call { orgsApi.listOrgs().map { it.toDomain() } }
    }

    override suspend fun listMembers(orgId: String): ApiResult<List<OrgMember>> =
        withContext(Dispatchers.IO) {
            call { orgsApi.listMembers(orgId).map { it.toDomain() } }
        }

    override suspend fun listPendingInvites(): ApiResult<List<OrgInvite>> =
        withContext(Dispatchers.IO) {
            call { orgsApi.listPendingInvites().map { it.toDomain() } }
        }

    override suspend fun inviteMember(
        orgId: String,
        email: String,
        role: OrgRole?,
    ): ApiResult<OrgInvite> = withContext(Dispatchers.IO) {
        call {
            // owner is NOT invitable: only an assignable role token (or null -> server default) is sent.
            val roleToken = role?.takeIf { it != OrgRole.OWNER && it != OrgRole.UNKNOWN }?.wire
            orgsApi.inviteMember(orgId, OrgMemberInviteReq(email = email, orgRole = roleToken)).toDomain()
        }
    }

    override suspend fun changeRole(
        orgId: String,
        memberSub: String,
        role: OrgRole,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            // owner is NOT assignable here; the wire token is one of admin|member|viewer.
            val token = role.wire ?: OrgRole.MEMBER.wire!!
            orgsApi.changeRole(orgId, memberSub, OrgMemberRoleUpdateReq(orgRole = token)).requireSuccess()
        }
    }

    override suspend fun removeMember(orgId: String, memberSub: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { orgsApi.removeMember(orgId, memberSub).requireSuccess() }
        }

    override suspend fun transferOwnership(
        orgId: String,
        newOwnerUserSub: String,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            orgsApi.transferOwnership(orgId, TransferOwnershipReq(newOwnerUserSub)).requireSuccess()
        }
    }

    override suspend fun leaveOrg(orgId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { orgsApi.leaveOrg(orgId).requireSuccess() }
        }

    override suspend fun acceptInvite(inviteId: String, token: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { orgsApi.acceptInvite(inviteId, OrgInviteAcceptReq(token = token)).requireSuccess() }
        }

    override suspend fun declineInvite(inviteId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call { orgsApi.declineInvite(inviteId).requireSuccess() }
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
     * Cancellation is re-thrown. Mirrors AND-340.
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
